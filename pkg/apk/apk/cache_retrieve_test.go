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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/paths"
)

// TestRetrieveAndSaveFileLeavesNoOrphans pins that a download into the cache
// leaves no temp file behind that the cache does not reference. The temp file
// is written in the cache directory and published by symlinking the cache file
// to it, so on success it is the cache entry's storage. On failure nothing
// links to it and nothing would ever remove it.
//
// Cleaning up a failed download must remove only that download's temp file,
// never the storage behind an entry that is already published. The rows with
// an existing entry advertise one first and check that it survives.
func TestRetrieveAndSaveFileLeavesNoOrphans(t *testing.T) {
	const (
		body    = "index contents"
		earlier = "earlier index contents"
	)
	complete := func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}
	cutShort := func(w http.ResponseWriter, _ *http.Request) {
		// Promise more than is sent, so the client sees the connection
		// close mid-body.
		w.Header().Set("Content-Length", "4096")
		_, _ = w.Write([]byte(body))
	}

	for _, tc := range []struct {
		name     string
		existing bool
		handler  http.HandlerFunc
		wantErr  string
		// wantBody, if set, is what the cache file must read back as.
		wantBody string
	}{{
		name:     "complete body is published",
		handler:  complete,
		wantBody: body,
	}, {
		name:    "body cut short is not left in the cache",
		handler: cutShort,
		wantErr: "unable to write to cache file",
	}, {
		name:     "body cut short leaves an existing entry intact",
		existing: true,
		handler:  cutShort,
		wantErr:  "unable to write to cache file",
		wantBody: earlier,
	}, {
		// Which copy wins is AdvertiseCachedFile's decision; what matters
		// here is that the entry still resolves and nothing is stranded.
		name:     "complete body over an existing entry leaves one live copy",
		existing: true,
		handler:  complete,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()

			cacheDir := filepath.Join(t.TempDir(), "APKINDEX")
			cacheFile := filepath.Join(cacheDir, "index.tar.gz")
			ct := &cacheTransport{wrapped: srv.Client()}

			if tc.existing {
				require.NoError(t, os.MkdirAll(cacheDir, 0o755))
				prev, err := os.CreateTemp(cacheDir, "*.tmp")
				require.NoError(t, err)
				_, err = prev.WriteString(earlier)
				require.NoError(t, err)
				require.NoError(t, prev.Close())
				require.NoError(t, paths.AdvertiseCachedFile(prev.Name(), cacheFile))
			}

			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
			require.NoError(t, err)

			got, err := ct.retrieveAndSaveFile(t.Context(), req, func(*http.Response) (string, error) {
				return cacheFile, nil
			})
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("retrieveAndSaveFile(%s): want success, got %v", tc.name, err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("retrieveAndSaveFile(%s): want error containing %q, got path=%q err=%v", tc.name, tc.wantErr, got, err)
			}

			if tc.wantErr == "" || tc.existing {
				data, err := os.ReadFile(cacheFile)
				if err != nil {
					t.Fatalf("cache file %s should resolve after %s: %v", cacheFile, tc.name, err)
				}
				if tc.wantBody != "" && string(data) != tc.wantBody {
					t.Fatalf("cache file %s after %s: got %q, want %q", cacheFile, tc.name, data, tc.wantBody)
				}
			}

			// Every temp file in the cache directory must be what the
			// cache file links to.
			target, _ := os.Readlink(cacheFile)
			entries, err := os.ReadDir(cacheDir)
			require.NoError(t, err)
			var orphans []string
			for _, e := range entries {
				if strings.HasSuffix(e.Name(), ".tmp") && e.Name() != target {
					orphans = append(orphans, e.Name())
				}
			}
			if len(orphans) != 0 {
				t.Errorf("cache directory holds unreferenced temp files %v (cache file links to %q)", orphans, target)
			}
		})
	}
}
