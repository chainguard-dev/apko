// Copyright 2023 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package apk

import (
	"context"
	"encoding/base32"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"go.opentelemetry.io/otel"
	"golang.org/x/sync/singleflight"

	"chainguard.dev/apko/pkg/paths"
)

type flightCache[T any] struct {
	flight *singleflight.Group
	cache  *sync.Map
}

// TODO: Consider [K, V] if we need a non-string key type.
func newFlightCache[T any]() *flightCache[T] {
	return &flightCache[T]{
		flight: &singleflight.Group{},
		cache:  &sync.Map{},
	}
}

// Do returns coalesces multiple calls, like singleflight, but also caches
// the result if the call is successful. Failures are not cached to avoid
// permanently failing for transient errors.
func (f *flightCache[T]) Do(key string, fn func() (T, error)) (T, error) {
	v, ok := f.cache.Load(key)
	if ok {
		if t, ok := v.(T); ok {
			return t, nil
		} else {
			// This can't happen but just in case things change.
			return t, fmt.Errorf("unexpected type %T", v)
		}
	}

	v, err, _ := f.flight.Do(key, func() (interface{}, error) {
		if v, ok := f.cache.Load(key); ok {
			return v, nil
		}

		// Don't cache errors, but maybe we should.
		v, err := fn()
		if err != nil {
			return nil, err
		}

		f.cache.Store(key, v)

		return v, nil
	})

	t, ok := v.(T)
	if err != nil {
		return t, err
	}
	if !ok {
		// This can't happen but just in case things change.
		return t, fmt.Errorf("unexpected type %T", v)
	}
	return t, nil
}

type Cache struct {
	etagCache  *sync.Map
	headFlight *singleflight.Group
	getFlight  *singleflight.Group

	discoverKeys *flightCache[[]Key]
}

// NewCache returns a new Cache, which allows us to persist the results of HEAD requests
// for a given URL across multiple builds. This is generally desirable when building many images
// all at once, since we can eliminate round trips to HEAD the same e.g. APKINDEX repeatedly.
// However, this is not desirable for long-lived processes where we expected the APKINDEX to change
// over time and want to observe those changes and re-fetch the new APKINDEX. Since apko is used
// in both contexts, this knob is exposed, but very few people actually should be using apko as a library,
// so I'm mostly just talking to myself here. This used to be a process-wide global cache, which was
// great for the short-lived terraform module, but a terrible default behavior for a library.
//
// Even if you don't want to cache HEAD requests, this is still useful for coalescing concurrent
// requests for the same resource when passing etag=false.
func NewCache(etag bool) *Cache {
	c := &Cache{
		headFlight:   &singleflight.Group{},
		getFlight:    &singleflight.Group{},
		discoverKeys: newFlightCache[[]Key](),
	}

	if etag {
		c.etagCache = &sync.Map{}
	}

	return c
}

func (c *Cache) load(cacheFile string) (*http.Response, bool) {
	if c == nil || c.etagCache == nil {
		return nil, false
	}

	v, ok := c.etagCache.Load(cacheFile)
	if !ok {
		return nil, false
	}

	return v.(*http.Response), true
}

func (c *Cache) store(cacheFile string, resp *http.Response) {
	if c == nil || c.etagCache == nil {
		return
	}

	c.etagCache.Store(cacheFile, resp)
}

// cache
type cache struct {
	dir     string
	offline bool

	shared *Cache
}

// client return an http.Client that knows how to read from and write to the cache
// key is in the implementation of https://pkg.go.dev/net/http#RoundTripper
func (c *cache) client(wrapped *http.Client, etagRequired bool) *http.Client {
	return &http.Client{
		Transport: &cacheTransport{
			cache:        c.shared,
			wrapped:      wrapped,
			root:         c.dir,
			offline:      c.offline,
			etagRequired: etagRequired,
		},
	}
}

type cacheTransport struct {
	cache        *Cache
	wrapped      *http.Client
	root         string
	offline      bool
	etagRequired bool
}

func (t *cacheTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	ctx, span := otel.Tracer("go-apk").Start(request.Context(), "cacheTransport.RoundTrip")
	defer span.End()

	cacheFile, err := cachePathFromURL(t.root, *request.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid cache path based on URL: %w", err)
	}

	if !t.etagRequired {
		// Try to open the file in the cache.
		// If we hit an error, just send the request.
		f, err := os.Open(cacheFile)
		if err != nil {
			if t.offline {
				return nil, fmt.Errorf("failed to read %q in offline cache: %w", cacheFile, err)
			}

			_, span := otel.Tracer("go-apk").Start(ctx, fmt.Sprintf("Request(%q)", request.URL.String()))
			defer span.End()

			// We don't cache the response for these because they get cached later in cachePackage.
			return t.wrapped.Do(request)
		}

		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       f,
		}, nil
	}

	if t.offline {
		return t.fetchOffline(cacheFile)
	}

	return t.fetchAndCache(ctx, request, cacheFile)
}

func (t *cacheTransport) head(request *http.Request, cacheFile string) (*http.Response, error) {
	resp, ok := t.cache.load(cacheFile)
	if ok {
		return resp, nil
	}

	v, err, _ := t.cache.headFlight.Do(cacheFile, func() (interface{}, error) {
		req := request.Clone(request.Context())
		req.Method = http.MethodHead
		resp, err := t.wrapped.Do(req)
		if err != nil {
			return nil, err
		}

		// HEAD shouldn't have a body. Make sure we close it so we can reuse the connection.
		defer resp.Body.Close()

		t.cache.store(cacheFile, resp)

		return resp, nil
	})
	if err != nil {
		return nil, err
	}

	return v.(*http.Response), nil
}

func (t *cacheTransport) get(ctx context.Context, request *http.Request, cacheFile, initialEtag string) (string, error) {
	v, err, _ := t.cache.getFlight.Do(cacheFile, func() (interface{}, error) {
		// We simulate content-based addressing with the etag values using an .etag file extension.
		etagFile, err := cacheFileFromEtag(cacheFile, initialEtag)
		if err != nil {
			return "", err
		}
		if _, err := os.Stat(etagFile); err == nil {
			return etagFile, nil
		}

		// Only download the index once.
		return t.retrieveAndSaveFile(ctx, request, func(r *http.Response) (string, error) {
			_, span := otel.Tracer("go-apk").Start(ctx, "callback")
			defer span.End()

			// On the etag path, use the etag from the actual response to compute the final file name.
			finalEtag, ok := etagFromResponse(r)
			if !ok {
				return "", fmt.Errorf("GET response did not contain an etag, but HEAD returned %q", initialEtag)
			}

			return cacheFileFromEtag(cacheFile, finalEtag)
		})
	})
	if err != nil {
		return "", err
	}

	return v.(string), nil
}

func (t *cacheTransport) fetchAndCache(ctx context.Context, request *http.Request, cacheFile string) (*http.Response, error) {
	initialEtag := request.Header.Get("I-Cant-Believe-Its-Not-If-None-Match")
	if initialEtag == "" {
		resp, err := t.head(request, cacheFile)
		if err != nil {
			return nil, err
		}

		if request.Method == http.MethodHead {
			return resp, err
		}

		etag, ok := etagFromResponse(resp)
		if !ok {
			return t.wrapped.Do(request)
		}

		initialEtag = etag
	}

	// This is a bit of a hack. We cache parsed APKINDEX files in globalIndexCache, which needs the etag as a cache key.
	// Since we already send a HEAD request to get that etag, we want to avoid sending a redundant HEAD request above if we can.
	// However, we don't actually want to pass along this header because it's using the "parsed" version of the Etag from
	// etagFromResponse and doesn't actually attempt to follow HTTP semantics, so we remove it here to avoid any confusion.
	request.Header.Del("I-Cant-Believe-Its-Not-If-None-Match")

	etagFile, err := t.get(ctx, request, cacheFile, initialEtag)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(etagFile)
	if err != nil {
		return nil, fmt.Errorf("open(%q): %w", etagFile, err)
	}

	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat(%q): %w", etagFile, err)
	}

	return &http.Response{
		StatusCode:    http.StatusOK,
		Body:          f,
		ContentLength: fi.Size(),
	}, nil
}

func (t *cacheTransport) fetchOffline(cacheFile string) (*http.Response, error) {
	cacheDir := cacheDirFromFile(cacheFile)
	des, err := os.ReadDir(cacheDir)
	if err != nil {
		return nil, fmt.Errorf("listing %q for offline cache: %w", cacheDir, err)
	}

	if len(des) == 0 {
		return nil, fmt.Errorf("no offline cached entries for %s", cacheDir)
	}

	newest, err := des[0].Info()
	if err != nil {
		return nil, err
	}

	for _, de := range des[1:] {
		fi, err := de.Info()
		if err != nil {
			return nil, err
		}

		if fi.ModTime().After(newest.ModTime()) {
			newest = fi
		}
	}

	f, err := os.Open(filepath.Join(cacheDir, newest.Name()))
	if err != nil {
		return nil, err
	}

	return &http.Response{
		StatusCode:    http.StatusOK,
		Body:          f,
		ContentLength: newest.Size(),
	}, nil
}

func cacheDirFromFile(cacheFile string) string {
	if strings.HasSuffix(cacheFile, "APKINDEX.tar.gz") {
		return filepath.Join(filepath.Dir(cacheFile), "APKINDEX")
	}

	return filepath.Dir(cacheFile)
}

func cacheFileFromEtag(cacheFile, etag string) (string, error) {
	cacheDir := filepath.Dir(cacheFile)
	ext := ".etag"

	// Keep all the index files under APKINDEX/ with appropriate file extension.
	if strings.HasSuffix(cacheFile, "APKINDEX.tar.gz") {
		cacheDir = filepath.Join(cacheDir, "APKINDEX")
		ext = ".tar.gz"
	}

	absPath, err := filepath.Abs(filepath.Join(cacheDir, etag+ext))
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(absPath, cacheDir) {
		return "", fmt.Errorf("unsafe etag value: %q", etag)
	}

	return absPath, nil
}

func etagFromResponse(resp *http.Response) (string, bool) {
	remoteEtag, ok := resp.Header[http.CanonicalHeaderKey("etag")]
	if !ok || len(remoteEtag) == 0 || remoteEtag[0] == "" {
		return "", false
	}
	// When we get etags, they appear to be quoted.
	etag := strings.Trim(remoteEtag[0], `"`)

	// To ensure these things are safe filenames, base32 encode them.
	// (Avoiding base64 due to case sensitive filesystems.)
	etag = base32.StdEncoding.EncodeToString([]byte(etag))

	return etag, etag != ""
}

type cachePlacer func(*http.Response) (string, error)

func (t *cacheTransport) retrieveAndSaveFile(ctx context.Context, request *http.Request, cp cachePlacer) (string, error) {
	_, span := otel.Tracer("go-apk").Start(ctx, "cacheTransport.retrieveAndSaveFile")
	defer span.End()

	if t.wrapped == nil {
		return "", fmt.Errorf("wrapped client is nil")
	}
	resp, err := t.wrapped.Do(request)
	if err != nil {
		return "", err
	} else if resp.StatusCode != 200 {
		return "", fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	// Determine the file we will caching stuff in based on the URL/response
	cacheFile, err := cp(resp)
	if err != nil {
		return "", err
	}
	cacheDir := filepath.Dir(cacheFile)
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return "", fmt.Errorf("unable to create cache directory: %w", err)
	}

	// Stream the request response to a temporary file within the final cache
	// directory
	tmp, err := os.CreateTemp(cacheDir, "*.tmp")
	if err != nil {
		return "", fmt.Errorf("unable to create a temporary cache file: %w", err)
	}
	// Now that symlinks are used to advertise cached files,
	// CreateTemp permissions are no longer suitable default,
	// update to world readable, group/user writable.
	// Ignore error, since some filesystem types don't support this,
	// and if this fails this should surface in other ways
	// (e.g. permission denied trying to read the file).
	_ = tmp.Chmod(os.FileMode(0664))

	if err := func() error {
		defer tmp.Close()
		defer resp.Body.Close()
		if _, err := io.Copy(tmp, resp.Body); err != nil {
			return fmt.Errorf("unable to write to cache file: %w", err)
		}
		return nil
	}(); err != nil {
		return "", err
	}

	// Now that we have the file has been written, rename to atomically populate
	// the cache
	if err := paths.AdvertiseCachedFile(tmp.Name(), cacheFile); err != nil {
		return "", err
	}
	return cacheFile, nil
}

func cacheDirForPackage(root string, pkg InstallablePackage) (string, error) {
	u, err := packageAsURL(pkg)
	if err != nil {
		return "", err
	}

	p, err := cachePathFromURL(root, *u)
	if err != nil {
		return "", err
	}

	if ext := filepath.Ext(p); ext != ".apk" {
		return "", fmt.Errorf("unexpected ext (%s) to cache dir: %q", ext, p)
	}

	return strings.TrimSuffix(p, ".apk"), nil
}

// cachePathFromURL given a URL, figure out what the cache path would be
func cachePathFromURL(root string, u url.URL) (string, error) {
	// the last two levels are what we append. For example https://example.com/foo/bar/x86_64/baz.apk
	// means we want to append x86_64/baz.apk to our cache root
	u2 := u
	u2.ForceQuery = false
	u2.RawFragment = ""
	u2.RawQuery = ""
	filename := filepath.Base(u2.Path)
	archDir := filepath.Dir(u2.Path)
	dir := filepath.Base(archDir)
	repoDir := filepath.Dir(archDir)
	// include the hostname
	u2.Path = repoDir

	// url encode it so it can be a single directory
	repoDir = url.QueryEscape(u2.String())
	cacheFile := filepath.Join(root, repoDir, dir, filename)
	// validate it is within root
	cacheFile = filepath.Clean(cacheFile)
	cleanroot := filepath.Clean(root)
	if !strings.HasPrefix(cacheFile, cleanroot) {
		return "", fmt.Errorf("cache file %s is not within root %s", cacheFile, cleanroot)
	}
	return cacheFile, nil
}
