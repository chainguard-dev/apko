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
	"testing"
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
