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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSubFSSymlinkUnderRoot(t *testing.T) {
	for name, newFS := range map[string]func(t *testing.T) FullFS{
		"memfs": func(*testing.T) FullFS { return NewMemFS() },
		"dirfs": func(t *testing.T) FullFS { return DirFS(t.Context(), t.TempDir()) },
	} {
		t.Run(name, func(t *testing.T) {
			base := newFS(t)
			require.NoError(t, base.MkdirAll("/sub/home", 0o755))
			require.NoError(t, base.MkdirAll("/home", 0o755))
			sub := &SubFS{FS: base, Root: "/sub"}

			// A relative target is stored as written, so it resolves against
			// the link's own directory inside the sub-filesystem.
			require.NoError(t, sub.Symlink("../etc/target", "/home/rel"))
			// An absolute target is also stored as written.
			require.NoError(t, sub.Symlink("/etc/target", "/home/abs"))
			// A relative link name, as tar headers carry them, also lands
			// under the root.
			require.NoError(t, sub.Symlink("/etc/target", "home/rel-name"))

			target, err := base.Readlink("/sub/home/rel")
			require.NoError(t, err)
			require.Equal(t, "../etc/target", target)
			target, err = base.Readlink("/sub/home/abs")
			require.NoError(t, err)
			require.Equal(t, "/etc/target", target)

			// Reading back through the SubFS agrees with the base view.
			target, err = sub.Readlink("/home/rel")
			require.NoError(t, err)
			require.Equal(t, "../etc/target", target)

			target, err = base.Readlink("/sub/home/rel-name")
			require.NoError(t, err)
			require.Equal(t, "/etc/target", target)

			// Nothing was created outside the root.
			for _, name := range []string{"rel", "abs", "rel-name"} {
				_, err = base.Lstat("/home/" + name)
				require.ErrorIs(t, err, os.ErrNotExist)
			}
		})
	}
}

func TestSubFSLinkUnderRoot(t *testing.T) {
	for name, newFS := range map[string]func(t *testing.T) FullFS{
		"memfs": func(*testing.T) FullFS { return NewMemFS() },
		"dirfs": func(t *testing.T) FullFS { return DirFS(t.Context(), t.TempDir()) },
	} {
		t.Run(name, func(t *testing.T) {
			base := newFS(t)
			require.NoError(t, base.MkdirAll("/sub/a", 0o755))
			require.NoError(t, base.MkdirAll("/sub/b", 0o755))
			require.NoError(t, base.MkdirAll("/a", 0o755))
			require.NoError(t, base.WriteFile("/sub/a/orig", []byte("inside"), 0o644))
			// A same-named file outside the root must not be the link source.
			require.NoError(t, base.WriteFile("/a/orig", []byte("outside"), 0o644))
			sub := &SubFS{FS: base, Root: "/sub"}

			require.NoError(t, sub.Link("/a/orig", "/b/hard"))
			// Relative names, as tar headers carry them, resolve the same way.
			require.NoError(t, sub.Link("a/orig", "b/hard-rel"))

			for _, name := range []string{"hard", "hard-rel"} {
				got, err := base.ReadFile("/sub/b/" + name)
				require.NoError(t, err)
				require.Equal(t, "inside", string(got))

				got, err = sub.ReadFile("/b/" + name)
				require.NoError(t, err)
				require.Equal(t, "inside", string(got))

				_, err = base.Lstat("/b/" + name)
				require.ErrorIs(t, err, os.ErrNotExist)
			}

			// Linking a source that only exists outside the root fails.
			require.NoError(t, base.WriteFile("/a/only-outside", []byte("x"), 0o644))
			require.ErrorIs(t, sub.Link("/a/only-outside", "/b/miss"), os.ErrNotExist)
		})
	}
}
