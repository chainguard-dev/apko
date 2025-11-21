// Copyright 2025 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestCacheTransport_ETagCollision_Integration is an end-to-end test that verifies
// the cache correctly handles duplicate ETags from different URLs. This tests the
// actual bug scenario from #1944 where Alpine Linux returns the same ETag for
// different signing keys.
func TestCacheTransport_ETagCollision_Integration(t *testing.T) {
	// Create a temp cache directory
	tmpDir := t.TempDir()

	// Track which URLs were requested
	requestedURLs := make(map[string]int)
	var mu sync.Mutex

	// Create a test server that simulates Alpine Linux behavior:
	// - Same ETag for different URLs
	// - Different content based on URL
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestedURLs[r.URL.Path]++
		mu.Unlock()

		// Return same ETag for all requests
		etag := "\"639a4604-320\""
		w.Header().Set("ETag", etag)

		// But return different content based on URL
		if r.Method == http.MethodHead {
			w.Header().Set("Content-Length", "28")
			w.WriteHeader(http.StatusOK)
			return
		}

		// Return unique content per URL so we can verify no collision
		var content []byte
		if strings.Contains(r.URL.Path, "616ae350") {
			content = []byte("x86_64-key-content-616ae350")
		} else if strings.Contains(r.URL.Path, "6165ee59") {
			content = []byte("aarch64-key-content-6165ee59")
		} else {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
		w.WriteHeader(http.StatusOK)
		w.Write(content)
	}))
	defer server.Close()

	// Create cache and transport
	sharedCache := NewCache(true)
	cache := &cache{
		dir:     tmpDir,
		offline: false,
		shared:  sharedCache,
	}

	baseClient := &http.Client{Transport: http.DefaultTransport}
	cachedClient := cache.client(baseClient, true)

	// Create two different URLs (simulating x86_64 and aarch64 keys)
	url1 := server.URL + "/keys/alpine-devel@lists.alpinelinux.org-616ae350.rsa.pub"
	url2 := server.URL + "/keys/alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub"

	// Fetch first key
	req1, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url1, nil)
	if err != nil {
		t.Fatalf("Failed to create request1: %v", err)
	}

	resp1, err := cachedClient.Do(req1)
	if err != nil {
		t.Fatalf("Failed to fetch first key: %v", err)
	}
	defer resp1.Body.Close()

	content1, err := io.ReadAll(resp1.Body)
	if err != nil {
		t.Fatalf("Failed to read first response: %v", err)
	}

	// Fetch second key (same ETag, different URL)
	req2, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url2, nil)
	if err != nil {
		t.Fatalf("Failed to create request2: %v", err)
	}

	resp2, err := cachedClient.Do(req2)
	if err != nil {
		t.Fatalf("Failed to fetch second key: %v", err)
	}
	defer resp2.Body.Close()

	content2, err := io.ReadAll(resp2.Body)
	if err != nil {
		t.Fatalf("Failed to read second response: %v", err)
	}

	// CRITICAL TEST: Different URLs with same ETag must return different content
	if string(content1) == string(content2) {
		t.Errorf("DUPLICATE ETAG BUG: Cache returned same content for different URLs!\n"+
			"URL1: %s\nURL2: %s\nContent1: %s\nContent2: %s",
			url1, url2, string(content1), string(content2))
	}

	// Verify we got the correct content for each URL
	if !strings.Contains(string(content1), "616ae350") {
		t.Errorf("First request got wrong content: %s", string(content1))
	}
	if !strings.Contains(string(content2), "6165ee59") {
		t.Errorf("Second request got wrong content: %s", string(content2))
	}

	// Verify both URLs were actually requested (not just one)
	mu.Lock()
	defer mu.Unlock()
	if requestedURLs["/keys/alpine-devel@lists.alpinelinux.org-616ae350.rsa.pub"] == 0 {
		t.Error("First URL was never requested")
	}
	if requestedURLs["/keys/alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub"] == 0 {
		t.Error("Second URL was never requested")
	}

	t.Logf("✅ Integration test passed: Different URLs with same ETag cached separately")
}

// TestCacheTransport_ConcurrentDuplicateETag verifies that concurrent fetches
// with duplicate ETags don't cause race conditions or cache corruption.
// This simulates the actual multi-arch build scenario.
func TestCacheTransport_ConcurrentDuplicateETag(t *testing.T) {
	tmpDir := t.TempDir()

	// Track concurrent requests
	var requestCounter int
	var counterMu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Same ETag for all
		w.Header().Set("ETag", "\"SAME-ETAG-FOR-ALL\"")

		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}

		counterMu.Lock()
		requestCounter++
		counterMu.Unlock()

		// Return unique content based on URL
		w.Write([]byte(fmt.Sprintf("content-for-%s", r.URL.Path)))
	}))
	defer server.Close()

	sharedCache := NewCache(true)
	cache := &cache{
		dir:     tmpDir,
		offline: false,
		shared:  sharedCache,
	}

	baseClient := &http.Client{Transport: http.DefaultTransport}
	cachedClient := cache.client(baseClient, true)

	// Launch concurrent fetches for 3 different URLs
	urls := []string{
		server.URL + "/keys/key1.pub",
		server.URL + "/keys/key2.pub",
		server.URL + "/keys/key3.pub",
	}

	var wg sync.WaitGroup
	results := make([]string, len(urls))
	errors := make([]error, len(urls))

	for i, url := range urls {
		wg.Add(1)
		go func(idx int, u string) {
			defer wg.Done()

			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u, nil)
			if err != nil {
				errors[idx] = err
				return
			}

			resp, err := cachedClient.Do(req)
			if err != nil {
				errors[idx] = err
				return
			}
			defer resp.Body.Close()

			content, err := io.ReadAll(resp.Body)
			if err != nil {
				errors[idx] = err
				return
			}

			results[idx] = string(content)
		}(i, url)
	}

	wg.Wait()

	// Check for errors
	for i, err := range errors {
		if err != nil {
			t.Errorf("Request %d failed: %v", i, err)
		}
	}

	// Verify all results are different (no cache corruption)
	for i := 0; i < len(results); i++ {
		for j := i + 1; j < len(results); j++ {
			if results[i] == results[j] {
				t.Errorf("Concurrent requests returned same content!\n"+
					"URL%d: %s\nURL%d: %s\nContent: %s",
					i, urls[i], j, urls[j], results[i])
			}
		}
	}

	// Verify each result contains its expected URL path
	for i, result := range results {
		expectedPath := fmt.Sprintf("/keys/key%d.pub", i+1)
		if !strings.Contains(result, expectedPath) {
			t.Errorf("Result %d doesn't contain expected path %s: %s", i, expectedPath, result)
		}
	}

	t.Logf("✅ Concurrency test passed: %d concurrent requests handled correctly", len(urls))
}

// TestCacheFileFromEtag_BackwardCompatibility documents the cache format change
// and verifies that old cache entries are not found after the URL hash fix.
// This is expected behavior and prevents cache pollution.
func TestCacheFileFromEtag_BackwardCompatibility(t *testing.T) {
	cacheFile := "/cache/keys/alpine-key.rsa.pub"
	etag := "TESTETAG123"

	// New format includes URL hash
	newPath, err := cacheFileFromEtag(cacheFile, etag)
	if err != nil {
		t.Fatalf("cacheFileFromEtag failed: %v", err)
	}

	// Verify new format contains both etag and hash (separated by -)
	basename := filepath.Base(newPath)
	if !strings.Contains(basename, etag) {
		t.Errorf("New format should contain etag: %s", basename)
	}
	if !strings.Contains(basename, "-") {
		t.Errorf("New format should contain hash separator: %s", basename)
	}

	// The old format would have been just: TESTETAG123.etag
	// The new format is: TESTETAG123-[8hexchars].etag
	parts := strings.Split(strings.TrimSuffix(basename, ".etag"), "-")
	if len(parts) != 2 {
		t.Errorf("Expected new format to be ETAG-HASH, got: %s", basename)
	}
	if len(parts) == 2 && len(parts[1]) != 8 {
		t.Errorf("Expected 8-character hash suffix, got %d characters: %s", len(parts[1]), parts[1])
	}

	t.Logf("Old format: TESTETAG123.etag")
	t.Logf("New format: %s", basename)
	t.Logf("✅ Cache format change documented - old entries won't be found (expected)")
}

// TestCacheFileFromEtag verifies basic cacheFileFromEtag behavior
func TestCacheFileFromEtag(t *testing.T) {
	t.Run("APKINDEX.tar.gz uses APKINDEX subdirectory", func(t *testing.T) {
		cacheFile := "/cache/repo/APKINDEX.tar.gz"
		etag := "INDEXETAG"

		result, err := cacheFileFromEtag(cacheFile, etag)
		if err != nil {
			t.Fatalf("cacheFileFromEtag() error = %v", err)
		}

		if !strings.Contains(result, "/APKINDEX/") {
			t.Errorf("Expected APKINDEX subdirectory, got: %s", result)
		}
		if !strings.HasSuffix(result, ".tar.gz") {
			t.Errorf("Expected .tar.gz extension, got: %s", result)
		}
		if !strings.Contains(result, etag) {
			t.Errorf("Expected result to contain etag, got: %s", result)
		}
	})
}

// TestCacheFileFromEtag_DuplicateETagCollision verifies that files with the same
// ETag but different URLs get different cache keys (the bug fix for #1944)
func TestCacheFileFromEtag_DuplicateETagCollision(t *testing.T) {
	// This simulates the Alpine Linux bug where different signing keys
	// return the same ETag: "639a4604-320" (encoded as GYZTSYJUGYYDILJTGIYA====)
	etag := "GYZTSYJUGYYDILJTGIYA===="

	// Two different key URLs that would have the same ETag
	cacheFile1 := "/cache/keys/alpine-devel@lists.alpinelinux.org-616ae350.rsa.pub"
	cacheFile2 := "/cache/keys/alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub"

	result1, err1 := cacheFileFromEtag(cacheFile1, etag)
	if err1 != nil {
		t.Fatalf("cacheFileFromEtag failed for file1: %v", err1)
	}

	result2, err2 := cacheFileFromEtag(cacheFile2, etag)
	if err2 != nil {
		t.Fatalf("cacheFileFromEtag failed for file2: %v", err2)
	}

	// The critical test: different URLs with same ETag MUST produce different cache paths
	if result1 == result2 {
		t.Errorf("DUPLICATE ETAG BUG: Different URLs with same ETag produced same cache path!\n"+
			"URL1: %s\nURL2: %s\nCache1: %s\nCache2: %s",
			cacheFile1, cacheFile2, result1, result2)
	}

	// Both should contain the etag
	if !strings.Contains(result1, etag) {
		t.Errorf("Result1 missing etag: %s", result1)
	}
	if !strings.Contains(result2, etag) {
		t.Errorf("Result2 missing etag: %s", result2)
	}

	// Both should be in the same directory (keys/)
	dir1 := filepath.Dir(result1)
	dir2 := filepath.Dir(result2)
	if dir1 != dir2 {
		t.Errorf("Expected same directory, got:\n  dir1: %s\n  dir2: %s", dir1, dir2)
	}

	t.Logf("✅ Cache collision prevented:\n  File1 -> %s\n  File2 -> %s", result1, result2)
}

// TestCacheFileFromEtag_APKINDEX verifies APKINDEX files maintain special handling
func TestCacheFileFromEtag_APKINDEX(t *testing.T) {
	cacheFile := "/cache/repo/x86_64/APKINDEX.tar.gz"
	etag := "APKINDEXETAG123"

	result, err := cacheFileFromEtag(cacheFile, etag)
	if err != nil {
		t.Fatalf("cacheFileFromEtag failed: %v", err)
	}

	// Should be in APKINDEX subdirectory
	if !strings.Contains(result, "/APKINDEX/") {
		t.Errorf("APKINDEX files should use APKINDEX subdirectory, got: %s", result)
	}

	// Should have .tar.gz extension
	if !strings.HasSuffix(result, ".tar.gz") {
		t.Errorf("APKINDEX files should have .tar.gz extension, got: %s", result)
	}

	// Should contain the etag
	if !strings.Contains(result, etag) {
		t.Errorf("Result should contain etag, got: %s", result)
	}

	t.Logf("✅ APKINDEX cache path: %s", result)
}

// TestCacheFileFromEtag_MultipleVersions verifies multiple versions of the same file
// with different ETags can coexist
func TestCacheFileFromEtag_MultipleVersions(t *testing.T) {
	cacheFile := "/cache/keys/release-key.rsa.pub"
	etag1 := "VERSION1"
	etag2 := "VERSION2"

	result1, err1 := cacheFileFromEtag(cacheFile, etag1)
	if err1 != nil {
		t.Fatalf("cacheFileFromEtag failed for version1: %v", err1)
	}

	result2, err2 := cacheFileFromEtag(cacheFile, etag2)
	if err2 != nil {
		t.Fatalf("cacheFileFromEtag failed for version2: %v", err2)
	}

	// Different ETags should produce different paths
	if result1 == result2 {
		t.Errorf("Different ETags should produce different cache paths, got same: %s", result1)
	}

	// Both should be in the same directory
	if filepath.Dir(result1) != filepath.Dir(result2) {
		t.Errorf("Same file with different versions should be in same directory")
	}

	t.Logf("✅ Multiple versions cached separately:\n  v1 -> %s\n  v2 -> %s", result1, result2)
}

// TestCacheFileFromEtag_PathTraversal verifies path traversal attempts are blocked
func TestCacheFileFromEtag_PathTraversal(t *testing.T) {
	tests := []struct {
		name      string
		cacheFile string
		etag      string
		wantErr   bool
	}{
		{
			name:      "normal file",
			cacheFile: "/cache/keys/normal.pub",
			etag:      "NORMALETAG",
			wantErr:   false,
		},
		{
			name:      "etag with path traversal attempt",
			cacheFile: "/cache/keys/normal.pub",
			etag:      "../../../etc/passwd",
			wantErr:   true,
		},
		{
			name:      "etag with dots (not traversal, just part of name)",
			cacheFile: "/cache/keys/normal.pub",
			etag:      "ETAG.WITH.DOTS",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := cacheFileFromEtag(tt.cacheFile, tt.etag)
			if (err != nil) != tt.wantErr {
				t.Errorf("cacheFileFromEtag() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && err == nil {
				// Verify result is within expected cache directory
				cacheDir := filepath.Dir(tt.cacheFile)
				if !strings.HasPrefix(result, cacheDir) {
					t.Errorf("Result path escaped cache directory:\n  cache: %s\n  result: %s",
						cacheDir, result)
				}
			}
		})
	}
}

// TestCacheDirFromFile verifies cache directory calculation
func TestCacheDirFromFile(t *testing.T) {
	tests := []struct {
		name      string
		cacheFile string
		want      string
	}{
		{
			name:      "APKINDEX gets APKINDEX subdirectory",
			cacheFile: "/cache/repo/x86_64/APKINDEX.tar.gz",
			want:      "/cache/repo/x86_64/APKINDEX",
		},
		{
			name:      "normal file returns parent directory",
			cacheFile: "/cache/keys/key.pub",
			want:      "/cache/keys",
		},
		{
			name:      "nested path returns parent",
			cacheFile: "/cache/repo/subdir/file.apk",
			want:      "/cache/repo/subdir",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cacheDirFromFile(tt.cacheFile)
			if got != tt.want {
				t.Errorf("cacheDirFromFile() = %v, want %v", got, tt.want)
			}
		})
	}
}
