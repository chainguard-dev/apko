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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"go.opentelemetry.io/otel"
)

// This is terrible but simpler than plumbing around a cache for now.
// We will assume that for a given process, we want to reuse etag values.
// Doing this cuts down on the number of requests we send for index and keys.
var globalEtagCache = &etagCache{}

type etagResp struct {
	resp      *http.Response
	err       error
	cacheFile string
}

type etagCache struct {
	// url -> *sync.Once
	etags sync.Map

	// url -> etagResp
	resps sync.Map
}

// get dedupes incoming etag-based requests by url (using a sync.Map[string]sync.Once) and stores the results
// in a sync.Map[string]etagResp. If we request the same URL multiple times, we will only ever reach out to
// the internet for the first once and reuse the results for all subsequent calls (unless the response does
// not have an etag).
func (e *etagCache) get(ctx context.Context, t *cacheTransport, request *http.Request, cacheFile string) (*http.Response, error) {
	ctx, span := otel.Tracer("go-apk").Start(ctx, fmt.Sprintf("etagCache.get(%q)", request.URL.String()))
	defer span.End()

	url := request.URL.String()

	// Do all the expensive things inside the once.
	once, _ := e.etags.LoadOrStore(url, &sync.Once{})
	once.(*sync.Once).Do(func() {
		ctx, span := otel.Tracer("go-apk").Start(ctx, "once.Do")
		defer span.End()

		req := request.Clone(request.Context())
		req.Method = http.MethodHead
		resp, rerr := t.wrapped.Do(req)
		if resp != nil {
			// We don't expect any body from a HEAD so just always close it to appease the linter.
			resp.Body.Close()
		}
		if rerr != nil || resp.StatusCode != 200 {
			e.resps.Store(url, etagResp{
				resp: resp,
				err:  rerr,
			})
			return
		}

		initialEtag, ok := etagFromResponse(resp)
		if !ok {
			return
		}

		// We simulate content-based addressing with the etag values using an .etag
		// file extension.
		etagFile := cacheFileFromEtag(cacheFile, initialEtag)
		if _, err := os.Stat(etagFile); err == nil {
			e.resps.Store(url, etagResp{
				cacheFile: etagFile,
			})
			return
		}

		// Only download the index once.
		etagFile, err := t.retrieveAndSaveFile(ctx, request, func(r *http.Response) (string, error) {
			_, span := otel.Tracer("go-apk").Start(ctx, "callback")
			defer span.End()
			// On the etag path, use the etag from the actual response to
			// compute the final file name.
			finalEtag, ok := etagFromResponse(r)
			if !ok {
				return "", fmt.Errorf("GET response did not contain an etag, but HEAD returned %q", initialEtag)
			}

			return cacheFileFromEtag(cacheFile, finalEtag), nil
		})
		e.resps.Store(url, etagResp{
			err:       err,
			cacheFile: etagFile,
		})
	})

	v, ok := e.resps.Load(url)
	if !ok {
		// If the server doesn't return etags, and we require them,
		// then do not cache.
		return t.wrapped.Do(request)
	}
	resp := v.(etagResp)

	// If we didn't manage to cache it, return the response and/or error.
	if resp.cacheFile == "" {
		return resp.resp, resp.err
	}

	f, err := os.Open(resp.cacheFile)
	if err != nil {
		return nil, fmt.Errorf("open(%q): %w", resp.cacheFile, err)
	}

	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat(%q): %w", resp.cacheFile, err)
	}

	return &http.Response{
		StatusCode:    http.StatusOK,
		Body:          f,
		ContentLength: fi.Size(),
	}, nil
}

// cache
type cache struct {
	dir     string
	offline bool
}

// client return an http.Client that knows how to read from and write to the cache
// key is in the implementation of https://pkg.go.dev/net/http#RoundTripper
func (c cache) client(wrapped *http.Client, etagRequired bool) *http.Client {
	return &http.Client{
		Transport: &cacheTransport{
			wrapped:      wrapped,
			root:         c.dir,
			offline:      c.offline,
			etagRequired: etagRequired,
		},
	}
}

type cacheTransport struct {
	wrapped      *http.Client
	root         string
	offline      bool
	etagRequired bool
}

func (t *cacheTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	ctx, span := otel.Tracer("go-apk").Start(request.Context(), "cacheTransport.RoundTrip")
	defer span.End()

	// do we have the file in the cache?
	if request.URL == nil {
		return nil, fmt.Errorf("no URL in request")
	}
	cacheFile, err := cachePathFromURL(t.root, *request.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid cache path based on URL: %w", err)
	}

	if !t.etagRequired {
		// We don't cache the response for these because they get cached later in cachePackage.

		ctx, span := otel.Tracer("go-apk").Start(ctx, fmt.Sprintf("Open(%q)", cacheFile))
		defer span.End()
		// Try to open the file in the cache.
		// If we hit an error, just send the request.
		f, err := os.Open(cacheFile)
		if err != nil {
			if t.offline {
				return nil, fmt.Errorf("failed to read %q in offline cache: %w", cacheFile, err)
			}
			_, span := otel.Tracer("go-apk").Start(ctx, fmt.Sprintf("Request(%q)", request.URL.String()))
			defer span.End()

			return t.wrapped.Do(request)
		}

		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       f,
		}, nil
	}

	if t.offline {
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

	return globalEtagCache.get(ctx, t, request, cacheFile)
}

func cacheDirFromFile(cacheFile string) string {
	if strings.HasSuffix(cacheFile, "APKINDEX.tar.gz") {
		return filepath.Join(filepath.Dir(cacheFile), "APKINDEX")
	}

	return filepath.Dir(cacheFile)
}

func cacheFileFromEtag(cacheFile, etag string) string {
	cacheDir := filepath.Dir(cacheFile)
	ext := ".etag"

	// Keep all the index files under APKINDEX/ with appropriate file extension.
	if strings.HasSuffix(cacheFile, "APKINDEX.tar.gz") {
		cacheDir = filepath.Join(cacheDir, "APKINDEX")
		ext = ".tar.gz"
	}

	return filepath.Join(cacheDir, etag+ext)
}

func etagFromResponse(resp *http.Response) (string, bool) {
	remoteEtag, ok := resp.Header[http.CanonicalHeaderKey("etag")]
	if !ok || len(remoteEtag) == 0 || remoteEtag[0] == "" {
		return "", false
	}
	// When we get etags, they appear to be quoted.
	etag := strings.Trim(remoteEtag[0], `"`)
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
	if err != nil || resp.StatusCode != 200 {
		return "", err
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
	if err := os.Rename(tmp.Name(), cacheFile); err != nil {
		return "", fmt.Errorf("unable to populate cache: %w", err)
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
