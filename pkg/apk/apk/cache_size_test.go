// Copyright 2026 Chainguard, Inc.
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
	"os"
	"sync"
	"testing"

	"chainguard.dev/apko/pkg/apk/expandapk"
)

// unsetenv removes name from the environment for the duration of the test
// and restores its previous value afterwards, so the test does not depend on
// what the caller's shell happens to export.
func unsetenv(t *testing.T, name string) {
	t.Helper()
	prev, had := os.LookupEnv(name)
	if err := os.Unsetenv(name); err != nil {
		t.Fatalf("unsetting %s: %v", name, err)
	}
	t.Cleanup(func() {
		if !had {
			return
		}
		if err := os.Setenv(name, prev); err != nil {
			t.Errorf("restoring %s: %v", name, err)
		}
	})
}

func TestCacheEntriesFromEnv(t *testing.T) {
	const name = "APKO_TEST_CACHE_ENTRIES"

	for _, tc := range []struct {
		name  string
		set   bool
		value string
		want  int
	}{
		{name: "unset uses default", set: false, want: 64},
		{name: "positive integer is honored", set: true, value: "512", want: 512},
		{name: "one is honored", set: true, value: "1", want: 1},
		{name: "zero falls back", set: true, value: "0", want: 64},
		{name: "negative falls back", set: true, value: "-3", want: 64},
		{name: "empty falls back", set: true, value: "", want: 64},
		{name: "non-numeric falls back", set: true, value: "lots", want: 64},
		{name: "float falls back", set: true, value: "1.5", want: 64},
		{name: "whitespace falls back", set: true, value: " 128", want: 64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv(name, tc.value)
			} else {
				unsetenv(t, name)
			}
			if got := cacheEntriesFromEnv(name, 64); got != tc.want {
				t.Errorf("cacheEntriesFromEnv(%q=%q) = %d, want %d", name, tc.value, got, tc.want)
			}
		})
	}
}

func TestPurgeCaches(t *testing.T) {
	key := cacheKey{url: "https://example.com/x86_64/APKINDEX.tar.gz", etag: "purge-test"}
	if _, _, err := globalIndexCache.indexes.Do(key, func() (NamedIndex, error) {
		return NewNamedRepositoryWithIndex("", (&Repository{}).WithIndex(&APKIndex{})), nil
	}); err != nil {
		t.Fatalf("filling index cache: %v", err)
	}
	indexes := []NamedIndex{NewNamedRepositoryWithIndex("purge-test", (&Repository{}).WithIndex(&APKIndex{}))}
	globalResolverCache.getOrFill(indexes, func() *PkgResolver { return &PkgResolver{} })
	globalDisqualifyCache.getOrFill(indexes, func() map[*RepositoryPackage]string { return nil })
	if _, _, err := globalApkCache.Do("https://example.com/purge-test.apk", func() (*expandapk.APKExpanded, error) {
		return &expandapk.APKExpanded{}, nil
	}); err != nil {
		t.Fatalf("filling package cache: %v", err)
	}

	cachedResolvePackageNameVersionPin("purge-test=1.0")
	if _, err := cachedParseVersion("1.0"); err != nil {
		t.Fatalf("filling version cache: %v", err)
	}

	internPackage(&Package{Name: "purge-test", Checksum: []byte("purge-test")})

	PurgeCaches()

	for name, n := range map[string]int{
		"index":      globalIndexCache.indexes.lru.Len(),
		"resolver":   globalResolverCache.len(),
		"disqualify": globalDisqualifyCache.len(),
		"package":    globalApkCache.lru.Len(),
		"version":    syncMapLen(&parsedVersions),
		"constraint": syncMapLen(&parsedConstraints),
		"intern":     len(packageInterner.m),
	} {
		if n != 0 {
			t.Errorf("%s cache entries after PurgeCaches = %d, want 0", name, n)
		}
	}
}

func syncMapLen(m *sync.Map) int {
	n := 0
	m.Range(func(any, any) bool {
		n++
		return true
	})
	return n
}
