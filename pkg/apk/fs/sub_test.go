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

package fs

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// subFSBases are the filesystems a SubFS is tested over.
var subFSBases = map[string]func(t *testing.T) FullFS{
	"memfs": func(*testing.T) FullFS { return NewMemFS() },
	"dirfs": func(t *testing.T) FullFS { return DirFS(t.Context(), t.TempDir()) },
}

func TestSubFSSymlinkUnderRoot(t *testing.T) {
	tests := []struct {
		name     string
		target   string // stored verbatim; never resolved by SubFS
		link     string // path given to SubFS
		wantPath string // where the link must land on the base FS
	}{
		{"relative target", "../etc/target", "/home/rel", "/sub/home/rel"},
		{"absolute target", "/etc/target", "/home/abs", "/sub/home/abs"},
		// Tar headers carry relative names.
		{"relative link name", "/etc/target", "home/rel-name", "/sub/home/rel-name"},
	}
	for baseName, newBase := range subFSBases {
		for _, tt := range tests {
			t.Run(baseName+"/"+tt.name, func(t *testing.T) {
				base := newBase(t)
				require.NoError(t, base.MkdirAll("/sub/home", 0o755))
				require.NoError(t, base.MkdirAll("/home", 0o755))
				sub := &SubFS{FS: base, Root: "/sub"}

				require.NoError(t, sub.Symlink(tt.target, tt.link))

				// The link lands under the root and stores the target as written.
				got, err := base.Readlink(tt.wantPath)
				require.NoError(t, err)
				require.Equal(t, tt.target, got)

				// Reading back through the SubFS agrees with the base view.
				got, err = sub.Readlink(tt.link)
				require.NoError(t, err)
				require.Equal(t, tt.target, got)

				// Nothing was created at the un-prefixed path outside the root.
				_, err = base.Lstat(strings.TrimPrefix(tt.wantPath, "/sub"))
				require.ErrorIs(t, err, os.ErrNotExist)
			})
		}
	}
}

func TestSubFSLinkUnderRoot(t *testing.T) {
	tests := []struct {
		name     string
		oldname  string // link source, a path on the SubFS
		newname  string // link to create, a path on the SubFS
		wantPath string // where the link must land on the base FS
		wantErr  error  // set when the source must not resolve
	}{
		{"absolute names", "/a/orig", "/b/hard", "/sub/b/hard", nil},
		// Tar headers carry relative names.
		{"relative names", "a/orig", "b/hard-rel", "/sub/b/hard-rel", nil},
		// A source that exists only outside the root is not reachable.
		{"source only outside the root", "/a/only-outside", "/b/miss", "", os.ErrNotExist},
	}
	for baseName, newBase := range subFSBases {
		for _, tt := range tests {
			t.Run(baseName+"/"+tt.name, func(t *testing.T) {
				base := newBase(t)
				require.NoError(t, base.MkdirAll("/sub/a", 0o755))
				require.NoError(t, base.MkdirAll("/sub/b", 0o755))
				require.NoError(t, base.MkdirAll("/a", 0o755))
				require.NoError(t, base.WriteFile("/sub/a/orig", []byte("inside"), 0o644))
				// Same-named files outside the root must never be the link source.
				require.NoError(t, base.WriteFile("/a/orig", []byte("outside"), 0o644))
				require.NoError(t, base.WriteFile("/a/only-outside", []byte("x"), 0o644))
				sub := &SubFS{FS: base, Root: "/sub"}

				err := sub.Link(tt.oldname, tt.newname)
				if tt.wantErr != nil {
					require.ErrorIs(t, err, tt.wantErr)
					return
				}
				require.NoError(t, err)

				// The link lands under the root and reads the inside file.
				got, err := base.ReadFile(tt.wantPath)
				require.NoError(t, err)
				require.Equal(t, "inside", string(got))

				// Reading back through the SubFS agrees with the base view.
				got, err = sub.ReadFile(tt.newname)
				require.NoError(t, err)
				require.Equal(t, "inside", string(got))

				// Nothing was created at the un-prefixed path outside the root.
				_, err = base.Lstat(strings.TrimPrefix(tt.wantPath, "/sub"))
				require.ErrorIs(t, err, os.ErrNotExist)
			})
		}
	}
}
