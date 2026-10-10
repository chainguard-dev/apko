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

package options

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/build/types"
)

// TestTempDir pins both ways Options.TempDir answers: a configured path is
// returned as is, and with none configured it creates one apko-temp-*
// directory under $TMPDIR and keeps returning it. Library callers that
// never set a temp dir rely on the second behaviour.
func TestTempDir(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configured bool
	}{
		{"configured path is returned without creating anything", true},
		{"unset path creates one apko-temp dir under TMPDIR and reuses it", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			t.Setenv("TMPDIR", tmp)

			var o Options
			want := ""
			if tc.configured {
				want = filepath.Join(t.TempDir(), "configured")
				o.TempDirPath = want
			}

			first, second := o.TempDir(), o.TempDir()

			entries, err := os.ReadDir(tmp)
			require.NoError(t, err)
			created := make([]string, 0, len(entries))
			for _, e := range entries {
				created = append(created, e.Name())
			}

			if tc.configured {
				if first != want || second != want || len(created) != 0 {
					t.Fatalf("TempDir() with TempDirPath=%q: got %q then %q, created %v in TMPDIR; want %q twice and nothing created", want, first, second, created, want)
				}
				return
			}
			if first != second || o.TempDirPath != first {
				t.Fatalf("TempDir() with no TempDirPath: got %q then %q (TempDirPath=%q); want the same path each time", first, second, o.TempDirPath)
			}
			if filepath.Dir(first) != tmp || !strings.HasPrefix(filepath.Base(first), "apko-temp-") {
				t.Fatalf("TempDir() with TMPDIR=%q: got %q; want an apko-temp-* directory directly under TMPDIR", tmp, first)
			}
			if len(created) != 1 {
				t.Fatalf("TempDir() called twice with TMPDIR=%q: created %v; want exactly one directory", tmp, created)
			}
			if fi, err := os.Stat(first); err != nil || !fi.IsDir() {
				t.Fatalf("TempDir() returned %q, which is not a directory: info=%v err=%v", first, fi, err)
			}
		})
	}
}

func TestLayerFileName(t *testing.T) {
	for _, tc := range []struct {
		name   string
		arch   types.Architecture
		format types.LayerFormat
		want   string
	}{
		{"tar with arch", types.ParseArchitecture("amd64"), types.LayerFormatTar, "apko-x86_64.tar.gz"},
		{"empty format defaults to tar", types.ParseArchitecture("amd64"), "", "apko-x86_64.tar.gz"},
		{"tar without arch", "", types.LayerFormatTar, "apko.tar.gz"},
		{"erofs with arch", types.ParseArchitecture("arm64"), types.LayerFormatErofs, "apko-aarch64.erofs"},
		{"erofs without arch", "", types.LayerFormatErofs, "apko.erofs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := Options{Arch: tc.arch}
			require.Equal(t, tc.want, o.LayerFileName(tc.format))
		})
	}
}

// The tar spelling must not drift from TarballFileName, which other callers
// still use directly.
func TestLayerFileName_MatchesTarballFileName(t *testing.T) {
	o := Options{Arch: types.ParseArchitecture("amd64")}
	require.Equal(t, o.TarballFileName(), o.LayerFileName(types.LayerFormatTar))
}
