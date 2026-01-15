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

package keyring

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"

	"chainguard.dev/apko/pkg/apk/auth"
	"go.lsp.dev/uri"
	"golang.org/x/sync/errgroup"
	"k8s.io/apimachinery/pkg/util/sets"
)

type KeyRing struct {
	alpineVersions sets.Set[string]
	discoveryURLs  sets.Set[string]

	jwksURLs               sets.Set[jwksURLInfo]
	keyURLs                sets.Set[string]
	unauthenticatedKeyURLs sets.Set[string]
	keyFiles               sets.Set[string]
}

// for backwards compatibility, we need to keep track of what
// discovery URL yielded what JWKS URL
type jwksURLInfo struct {
	url          string
	discoveryURL string
}

func NewKeyRing(opts ...KeyRingOption) (*KeyRing, error) {
	kr := &KeyRing{
		alpineVersions: sets.New[string](),
		discoveryURLs:  sets.New[string](),

		jwksURLs:               sets.New[jwksURLInfo](),
		keyURLs:                sets.New[string](),
		unauthenticatedKeyURLs: sets.New[string](),
		keyFiles:               sets.New[string](),
	}

	for _, opt := range opts {
		if err := opt(kr); err != nil {
			return nil, err
		}
	}

	return kr, nil
}

type KeyRingOption func(*KeyRing) error

func AddKeyPaths(keyPaths ...string) KeyRingOption {
	return func(kr *KeyRing) error {
		for _, keyPath := range keyPaths {
			var asURL *url.URL
			var err error
			if strings.HasPrefix(keyPath, "https://") || strings.HasPrefix(keyPath, "http://") {
				asURL, err = url.Parse(keyPath)
			} else {
				// Attempt to parse non-https elements into URI's so they are translated into
				// file:// URLs allowing them to parse into a url.URL{}
				asURL, err = url.Parse(string(uri.New(keyPath)))
			}
			if err != nil {
				return fmt.Errorf("failed to parse key as URI: %w", err)
			}

			switch asURL.Scheme {
			case "file": //nolint:goconst
				kr.keyFiles.Insert(keyPath)
			case "https", "http": //nolint:goconst
				kr.keyURLs.Insert(asURL.String())
			default:
				return fmt.Errorf("scheme %s not supported", asURL.Scheme)
			}
		}

		return nil
	}
}

func AddRepositories(repositories ...string) KeyRingOption {
	return func(kr *KeyRing) error {
		for _, repository := range repositories {
			if !strings.HasPrefix(repository, "https://") && !strings.HasPrefix(repository, "http://") {
				// Ignore non-remote repositories.
				continue
			}

			if version, ok := parseAlpineVersion(repository); ok {
				kr.alpineVersions.Insert(version)
			}

			discoveryURL, err := url.Parse(strings.TrimSuffix(repository, "/") + "/apk-configuration")
			if err != nil {
				return fmt.Errorf("failed to parse repository URL: %w", err)
			}
			kr.discoveryURLs.Insert(discoveryURL.String())
		}

		return nil
	}
}

var repoRE = regexp.MustCompile(`^http[s]?://.+\/alpine\/([^\/]+)\/[^\/]+$`)

// parseAlpineVersion parses the Alpine version from a repository URL.
// Returns the version string (e.g., "v3.21") and true if successful.
func parseAlpineVersion(repo string) (version string, ok bool) {
	parts := repoRE.FindStringSubmatch(repo)
	if len(parts) < 2 {
		return "", false
	}
	return parts[1], true
}

type Key struct {
	ID    string
	Bytes []byte
	URL   string
}

type Fetcher func(ctx context.Context, url string, authenticated bool) (*http.Response, error)

func NewFetcher(client *http.Client, auth auth.Authenticator) Fetcher {
	return func(ctx context.Context, url string, authenticated bool) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}

		if authenticated && auth != nil {
			if err := auth.AddAuth(ctx, req); err != nil {
				return nil, err
			}
		}

		return client.Do(req)
	}
}

func (kr *KeyRing) FetchKeys(ctx context.Context, fetcher Fetcher, archs []string) ([]Key, error) {
	{
		errgroup, gctx := errgroup.WithContext(ctx)
		var alpineKeyURLs []string
		if len(kr.alpineVersions) > 0 {
			errgroup.Go(func() error {
				alpineURLs, err := fetchAlpineKeyURLs(gctx, fetcher, archs, kr.alpineVersions.UnsortedList())
				if err != nil {
					return fmt.Errorf("failed to fetch alpine key URLs for versions %v: %w", kr.alpineVersions.UnsortedList(), err)
				}

				alpineKeyURLs = alpineURLs
				return nil
			})
		}

		discoveryURLs := kr.discoveryURLs.UnsortedList()
		jwksURLs := make([]jwksURLInfo, len(discoveryURLs))
		for i, discoveryURL := range discoveryURLs {
			errgroup.Go(func() error {
				jwksURL, err := fetchJWKSURLFromDiscovery(gctx, fetcher, discoveryURL)
				if err != nil {
					return fmt.Errorf("failed to fetch JWKS URL from discovery URL %q: %w", discoveryURL, err)
				}

				jwksURLs[i] = jwksURLInfo{
					url:          jwksURL,
					discoveryURL: discoveryURL,
				}
				return nil
			})
		}

		if err := errgroup.Wait(); err != nil {
			return nil, err
		}

		kr.unauthenticatedKeyURLs.Insert(alpineKeyURLs...)
		kr.jwksURLs.Insert(jwksURLs...)
	}

	var keys []Key
	{
		var mu sync.Mutex
		errgroup, gctx := errgroup.WithContext(ctx)
		for _, jwksURL := range kr.jwksURLs.UnsortedList() {
			if jwksURL.url == "" {
				continue // jwksURLs may have empty entries if discovery returned 404
			}

			errgroup.Go(func() error {
				jwksKeys, err := fetchKeysFromJWKS(gctx, fetcher, jwksURL)
				if err != nil {
					return fmt.Errorf("failed to fetch keys from JWKS URL %q: %w", jwksURL, err)
				}

				mu.Lock()
				defer mu.Unlock()
				keys = append(keys, jwksKeys...)
				return nil
			})
		}

		for _, keyURL := range kr.keyURLs.UnsortedList() {
			errgroup.Go(func() error {
				key, err := fetchKeyFromURL(gctx, fetcher, keyURL, true)
				if err != nil {
					return fmt.Errorf("failed to fetch key from URL %q: %w", keyURL, err)
				}

				mu.Lock()
				defer mu.Unlock()
				keys = append(keys, key)
				return nil
			})
		}

		for _, keyURL := range kr.unauthenticatedKeyURLs.UnsortedList() {
			errgroup.Go(func() error {
				key, err := fetchKeyFromURL(gctx, fetcher, keyURL, false)
				if err != nil {
					return fmt.Errorf("failed to fetch key from URL %q (unauthenticated): %w", keyURL, err)
				}

				mu.Lock()
				defer mu.Unlock()
				keys = append(keys, key)
				return nil
			})
		}

		if err := errgroup.Wait(); err != nil {
			return nil, err
		}

		for _, keyFile := range kr.keyFiles.UnsortedList() {
			keyData, err := os.ReadFile(keyFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read apk key file %q: %w", keyFile, err)
			}

			mu.Lock()
			defer mu.Unlock()
			keys = append(keys, Key{
				ID:    filepath.Base(keyFile),
				Bytes: keyData,
				URL:   keyFile,
			})
		}
	}

	// sort slice
	slices.SortFunc(keys, func(a, b Key) int {
		idCompare := strings.Compare(a.ID, b.ID)
		if idCompare != 0 {
			return idCompare
		}

		return bytes.Compare(a.Bytes, b.Bytes)
	})

	// drop any duplicates
	keys = slices.CompactFunc(keys, func(a, b Key) bool {
		return a.ID == b.ID && bytes.Equal(a.Bytes, b.Bytes)
	})

	// add suffix to duplicate IDs
	suffixCounter := 1
	for i, key := range keys {
		if i == 0 {
			continue
		}

		if key.ID != keys[i-1].ID {
			suffixCounter = 1
			continue
		}

		suffixCounter++
		if strings.HasSuffix(key.ID, ".rsa.pub") {
			keys[i].ID = fmt.Sprintf("%s-%d.rsa.pub", strings.TrimSuffix(key.ID, ".rsa.pub"), suffixCounter)
		} else {
			keys[i].ID = fmt.Sprintf("%s-%d", key.ID, suffixCounter)
		}
	}

	return keys, nil
}
