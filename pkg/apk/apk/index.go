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
	"archive/tar"
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/chainguard-dev/clog"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/klauspost/compress/gzip"
	"go.lsp.dev/uri"
	"go.opentelemetry.io/otel"
	"golang.org/x/sync/errgroup"

	"chainguard.dev/apko/pkg/apk/auth"
	sign "chainguard.dev/apko/pkg/apk/signature"
)

var signatureFileRegex = regexp.MustCompile(`^\.SIGN\.(DSA|RSA|RSA256|RSA512)\.(.*\.rsa\.pub)$`)

type Signature struct {
	KeyID           string
	Signature       []byte
	DigestAlgorithm crypto.Hash
}

// This is terrible but simpler than plumbing around a cache for now.
// We just hold the parsed index in memory rather than re-parsing it every time,
// which requires gunzipping, which is (somewhat) expensive.
var globalIndexCache = &indexCache{
	modtimes: map[string]time.Time{},
	indexes: func() *lru.Cache[cacheKey, func() (NamedIndex, error)] {
		indexCacheSize := 100 // Unscientific default size.
		if v := os.Getenv("APKO_INDEX_CACHE_SIZE"); v != "" {
			size, err := strconv.Atoi(v)
			if err != nil {
				panic(fmt.Sprintf("invalid APKO_INDEX_CACHE_SIZE %q: %v", v, err))
			}
			indexCacheSize = size
		}

		// This only fails for negative cache sizes, so we can ignore the error.
		c, _ := lru.New[cacheKey, func() (NamedIndex, error)](indexCacheSize)
		return c
	}(),
}

type cacheKey struct {
	url  string
	etag string // Only used for remote indexes.
}

type indexCache struct {
	indexesMux sync.Mutex // To make up for the lack of atomic GetOrAdd in lru.Cache.
	indexes    *lru.Cache[cacheKey, func() (NamedIndex, error)]

	// For local indexes.
	sync.Mutex
	modtimes map[string]time.Time
}

func (i *indexCache) get(ctx context.Context, repoName, repoURL string, keys map[string][]byte, arch string, opts *indexOpts) (NamedIndex, error) {
	u := IndexURL(repoURL, arch)

	ctx, span := otel.Tracer("go-apk").Start(ctx, fmt.Sprintf("indexCache.get(%q)", u))
	defer span.End()

	repoBase := fmt.Sprintf("%s/%s", repoURL, arch)
	repoRef := Repository{URI: repoBase}

	if strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "http://") {
		asURL, err := url.Parse(u)
		if err != nil {
			return nil, fmt.Errorf("parsing repo: %w", err)
		}

		// We usually don't want remote indexes to change while we're running.
		// But sometimes, we do, in which case we want to key off of the etag.
		// We can use a separate etag cache in the httpClient to avoid the HEAD
		// if it's set, but if it's not set we need to do a HEAD each time.
		client := opts.httpClient
		head, err := http.NewRequestWithContext(ctx, http.MethodHead, u, nil)
		if err != nil {
			return nil, err
		}
		if opts.auth == nil {
			opts.auth = auth.DefaultAuthenticators
		}
		if err := opts.auth.AddAuth(ctx, head); err != nil {
			return nil, fmt.Errorf("unable to add auth to request: %w", err)
		}

		resp, err := client.Do(head)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("unexpected status code %d", resp.StatusCode)
		}

		fetchAndParse := func(etag string) (NamedIndex, error) {
			b, err := fetchRepositoryIndex(ctx, u, etag, opts)
			if err != nil {
				return nil, fmt.Errorf("fetching %s: %w", asURL.Redacted(), err)
			}
			idx, err := parseRepositoryIndex(ctx, u, keys, arch, b, opts)
			if err != nil {
				return nil, fmt.Errorf("parsing %s: %w", asURL.Redacted(), err)
			}
			return NewNamedRepositoryWithIndex(repoName, repoRef.WithIndex(idx)), nil
		}

		etag, ok := etagFromResponse(resp)
		if !ok {
			// If there's no etag, we can't cache it, so just return the result.
			return fetchAndParse(etag)
		}

		key := cacheKey{url: u, etag: etag}
		entry, ok := i.indexes.Get(key)
		if !ok {
			i.indexesMux.Lock()
			// There's no atomic GetOrAdd in the lru.Cache, so we need to check again under the lock.
			entry, ok = i.indexes.Get(key)
			if ok {
				// If there is an entry now, there was a race to the Get above. We can just return now.
				i.indexesMux.Unlock()
				return entry()
			}

			// If there is no entry yet, we create the sync.OnceValues instance to do the fetch and
			// immediately add it to the cache. Others will see it and attach to it. It functions
			// kind of like a cached future.
			entry = sync.OnceValues(func() (NamedIndex, error) {
				idx, err := fetchAndParse(etag)
				if err != nil {
					// We don't want to cache errors, so we remove the entry.
					i.indexes.Remove(key)
				}
				return idx, err
			})
			i.indexes.Add(key, entry)

			// Unlock after adding the entry to the cache. Note that we've not actually executed
			// the function yet, so this will not block over network calls.
			i.indexesMux.Unlock()

			// Remove any stale entries with the same URL but different etag.
			for _, key := range i.indexes.Keys() {
				if key.url == u && key.etag != etag {
					i.indexes.Remove(key)
				}
			}
		}
		return entry()
	} else {
		i.Lock()
		defer i.Unlock()

		// We do expect local indexes to change, so we check modtimes.
		stat, err := os.Stat(u)
		if err != nil {
			return nil, fmt.Errorf("stat: %w", err)
		}

		key := cacheKey{url: u}
		entry, hasCachedValue := i.indexes.Get(key)

		mod := stat.ModTime()
		before, ok := i.modtimes[u]
		if !hasCachedValue || !ok || mod.After(before) {
			b, err := os.ReadFile(u)
			if err != nil {
				return nil, fmt.Errorf("reading file: %w", err)
			}

			entry = sync.OnceValues(func() (NamedIndex, error) {
				idx, err := parseRepositoryIndex(ctx, u, keys, arch, b, opts)
				if err != nil {
					return nil, err
				}
				return NewNamedRepositoryWithIndex(repoName, repoRef.WithIndex(idx)), nil
			})

			i.indexes.Add(key, entry)
			i.modtimes[u] = mod
		}

		return entry()
	}
}

// IndexURL returns the full URL to the index file for the given repo and arch.
//
// `repo` is the URL of the repository including the protocol, e.g.
// "https://packages.wolfi.dev/os".
//
// `arch` is the architecture of the index, e.g. "x86_64" or "aarch64".
func IndexURL(repo, arch string) string {
	return fmt.Sprintf("%s/%s/%s", repo, arch, indexFilename)
}

// GetRepositoryIndexes returns the indexes for the named repositories, keys and archs.
// The signatures for each index are verified unless ignoreSignatures is set to true.
// The key-value pairs in the map for `keys` are the name of the key and the contents of the key.
// The name is just indicative. If it finds a match, it will use it. Else, it will try all keys.
func GetRepositoryIndexes(ctx context.Context, repos []string, keys map[string][]byte, arch string, options ...IndexOption) ([]NamedIndex, error) {
	ctx, span := otel.Tracer("go-apk").Start(ctx, "GetRepositoryIndexes")
	defer span.End()

	opts := &indexOpts{}
	for _, opt := range options {
		opt(opts)
	}

	indexes := make([]NamedIndex, len(repos))

	var eg errgroup.Group
	for i, repo := range repos {
		i, repo := i, repo

		eg.Go(func() error {
			// does it start with a pin?
			var (
				repoName string
				repoURL  = repo
			)
			if strings.HasPrefix(repo, "@") {
				// it's a pinned repository, get the name
				parts := strings.Fields(repo)
				if len(parts) < 2 {
					return fmt.Errorf("invalid repository line: %q", repo)
				}
				repoName = parts[0][1:]
				repoURL = parts[1]
			}

			index, err := globalIndexCache.get(ctx, repoName, repoURL, keys, arch, opts)
			if err != nil {
				redacted := redact(IndexURL(repoURL, arch))
				if errors.Is(err, fs.ErrNotExist) {
					// This can happen for local repos, just log and continue.
					clog.WarnContextf(ctx, "getting local index %s: %v", redacted, err)
					return nil
				}

				return fmt.Errorf("reading index %s: %w", redacted, err)
			}

			indexes[i] = index
			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return nil, err
	}

	indexes = slices.DeleteFunc(indexes, func(idx NamedIndex) bool {
		return idx == nil
	})

	return indexes, nil
}

func shouldCheckSignatureForIndex(index string, arch string, opts *indexOpts) bool {
	if opts.ignoreSignatures {
		return false
	}
	for _, ignoredIndex := range opts.noSignatureIndexes {
		if IndexURL(ignoredIndex, arch) == index {
			return false
		}
	}
	return true
}

func fetchRepositoryIndex(ctx context.Context, u string, etag string, opts *indexOpts) ([]byte, error) { //nolint:gocyclo
	client := opts.httpClient
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}

	if etag != "" {
		// This is a hack, I'm sorry, but it's the only way to avoid modifying our weird transportCache too much.
		// Earlier, we check the etag value to avoid re-parsing the APKINDEX if it hasn't changed, but the transport
		// also really wants to do a HEAD request in order to do etag-based caching itself. To avoid the double HEAD,
		// I'm stuffing the etag into the If-None-Match header, which isn't exactly correct semantics but it rhymes.
		// The alternative is to rewrite everything, which I don't have time to do right now, so it is what it is.
		req.Header.Set("I-Cant-Believe-Its-Not-If-None-Match", etag)
	}

	if opts.auth == nil {
		opts.auth = auth.DefaultAuthenticators
	}
	if err := opts.auth.AddAuth(ctx, req); err != nil {
		return nil, fmt.Errorf("unable to add auth to request: %w", err)
	}

	// This will return a body that retries requests using Range requests if Read() hits an error.
	rrt := newRangeRetryTransport(ctx, client)
	res, err := rrt.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d", res.StatusCode)
	}
	defer res.Body.Close()

	b, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("reading body: %w", err)
	}

	return b, nil
}

func parseRepositoryIndex(ctx context.Context, u string, keys map[string][]byte, arch string, b []byte, opts *indexOpts) (*APKIndex, error) { //nolint:gocyclo
	_, span := otel.Tracer("go-apk").Start(ctx, "parseRepositoryIndex")
	defer span.End()
	// validate the signature
	if shouldCheckSignatureForIndex(u, arch, opts) {
		if len(keys) == 0 {
			return nil, fmt.Errorf("no keys provided to verify signature")
		}
		// check that they key name aren't paths or URLs
		for keyName := range keys {
			if strings.Contains(keyName, "/") {
				return nil, fmt.Errorf("invalid keyname %q", keyName)
			}
		}
		buf := bytes.NewReader(b)
		gzipReader, err := gzip.NewReader(buf)
		if err != nil {
			return nil, fmt.Errorf("unable to create gzip reader for repository index: %w", err)
		}
		// set multistream to false, so we can read each part separately;
		// the first part is the signature, the second is the index, which should be
		// verified.
		gzipReader.Multistream(false)
		defer gzipReader.Close()

		tarReader := tar.NewReader(gzipReader)

		sigs := make([]Signature, 0, len(keys))

		for {
			// read the signature(s)
			signatureFile, err := tarReader.Next()
			// found everything, end of stream
			if errors.Is(err, io.EOF) {
				break
			}
			// oops something went wrong
			if err != nil {
				return nil, fmt.Errorf("unexpected error reading from tgz: %w", err)
			}
			matches := signatureFileRegex.FindStringSubmatch(signatureFile.Name)
			if len(matches) != 3 {
				return nil, fmt.Errorf("failed to find key name in signature file name: %s", signatureFile.Name)
			}
			keyfile := matches[2]

			trimmedKeyFile := strings.TrimSuffix(keyfile, ".rsa.pub")
			if _, ok := keys[keyfile]; ok {
				// We found a matching key
			} else if _, ok := keys[trimmedKeyFile]; ok {
				// When we download keys from proxy servers - like artifactory, we ignore the 'content-disposition' header
				// (that would be difficult to cache as well), and the header is responsible for providing key name with
				// proper extension. Here we accept matching keys without proper extension.
				keyfile = trimmedKeyFile
			} else {
				clog.FromContext(ctx).Warnf("skipping signature %s due to missing keyfile: %s", signatureFile.Name, keyfile)
				// Ignore this signature if we don't have the key
				continue
			}
			var digestAlgorithm crypto.Hash
			switch signatureType := matches[1]; signatureType {
			case "DSA":
				// Obsolete
				continue
			case "RSA":
				// Current legacy compat
				digestAlgorithm = crypto.SHA1
			case "RSA256":
				// Current best practice
				digestAlgorithm = crypto.SHA256
			case "RSA512":
				// Too big, too slow, not compiled in
				continue
			default:
				return nil, fmt.Errorf("unknown signature format: %s", signatureType)
			}
			signature, err := io.ReadAll(tarReader)
			if err != nil {
				return nil, fmt.Errorf("failed to read signature from repository index: %w", err)
			}
			sigs = append(sigs, Signature{
				KeyID:           keyfile,
				Signature:       signature,
				DigestAlgorithm: digestAlgorithm,
			})
		}
		if len(sigs) == 0 {
			return nil, fmt.Errorf("no signature with known key (one of: %v) found in repository index", slices.Collect(maps.Keys(keys)))
		}
		// we now have the signature bytes and name, get the contents of the rest;
		// this should be everything else in the raw gzip file as is.
		allBytes := len(b)
		unreadBytes := buf.Len()
		readBytes := allBytes - unreadBytes
		indexData := b[readBytes:]
		indexDigest := make(map[crypto.Hash][]byte, len(keys))
		verified := false
		for _, sig := range sigs {
			// compute the digest if not already done
			if _, hasDigest := indexDigest[sig.DigestAlgorithm]; !hasDigest {
				h := sig.DigestAlgorithm.New()
				if n, err := h.Write(indexData); err != nil || n != len(indexData) {
					return nil, fmt.Errorf("unable to hash data: %w", err)
				}
				indexDigest[sig.DigestAlgorithm] = h.Sum(nil)
			}
			if err := sign.RSAVerifyDigest(indexDigest[sig.DigestAlgorithm], sig.DigestAlgorithm, sig.Signature, keys[sig.KeyID]); err == nil {
				verified = true
				break
			} else {
				clog.FromContext(ctx).Warnf("failed to verify signature for keyfile %s: %v", sig.KeyID, err)
			}
		}
		if !verified {
			return nil, errors.New("signature verification failed for repository index, for all provided keys")
		}
	}
	// with a valid signature, convert it to an ApkIndex
	index, err := IndexFromArchive(io.NopCloser(bytes.NewReader(b)))
	if err != nil {
		return nil, fmt.Errorf("unable to read convert repository index bytes to index struct: %w", err)
	}

	return index, err
}

type indexOpts struct {
	ignoreSignatures   bool
	noSignatureIndexes []string
	httpClient         *http.Client
	auth               auth.Authenticator
}
type IndexOption func(*indexOpts)

func WithIgnoreSignatures(ignoreSignatures bool) IndexOption {
	return func(o *indexOpts) {
		o.ignoreSignatures = ignoreSignatures
	}
}

func WithIgnoreSignatureForIndexes(noSignatureIndexes ...string) IndexOption {
	return func(o *indexOpts) {
		o.noSignatureIndexes = append(o.noSignatureIndexes, noSignatureIndexes...)
	}
}

func WithHTTPClient(c *http.Client) IndexOption {
	return func(o *indexOpts) {
		o.httpClient = c
	}
}

func WithIndexAuthenticator(a auth.Authenticator) IndexOption {
	return func(o *indexOpts) {
		o.auth = a
	}
}

func redact(in string) string {
	asURL, err := url.Parse(in)
	if err != nil {
		// Attempt to parse non-https elements into URI's so they are translated into
		// file:// URLs allowing them to parse into a url.URL{}
		asURL, err := url.Parse(string(uri.New(in)))
		if err != nil {
			return in
		}

		return asURL.Redacted()
	}

	return asURL.Redacted()
}
