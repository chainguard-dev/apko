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
	"archive/tar"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLchownDoesNotFollowSymlink(t *testing.T) {
	for name, newFS := range map[string]func(t *testing.T) FullFS{
		"memfs": func(*testing.T) FullFS { return NewMemFS() },
		"dirfs": func(t *testing.T) FullFS { return DirFS(t.Context(), t.TempDir()) },
	} {
		t.Run(name, func(t *testing.T) {
			fsys := newFS(t)
			require.NoError(t, fsys.MkdirAll("/etc", 0o755))
			require.NoError(t, fsys.WriteFile("/etc/target", []byte("x"), 0o644))
			require.NoError(t, fsys.MkdirAll("/home", 0o755))
			require.NoError(t, fsys.Symlink("/etc/target", "/home/link"))
			require.NoError(t, fsys.Symlink("/does/not/exist", "/home/dangling"))

			lfs, ok := fsys.(LchownFS)
			require.True(t, ok, "%T does not implement LchownFS", fsys)
			require.NoError(t, lfs.Lchown("/home/link", 999, 998))
			require.NoError(t, lfs.Lchown("/home/dangling", 999, 998))
			require.Error(t, lfs.Lchown("/home/missing", 999, 998))

			fi, err := fsys.Stat("/etc/target")
			require.NoError(t, err)
			hdr, ok := fi.Sys().(*tar.Header)
			require.True(t, ok)
			require.Equal(t, 0, hdr.Uid, "target uid changed")
			require.Equal(t, 0, hdr.Gid, "target gid changed")

			des, err := fsys.ReadDir("/home")
			require.NoError(t, err)
			require.Len(t, des, 2)
			for _, de := range des {
				info, err := de.Info()
				require.NoError(t, err)
				hdr, ok := info.Sys().(*tar.Header)
				require.True(t, ok)
				require.Equal(t, 999, hdr.Uid, "uid of %s", de.Name())
				require.Equal(t, 998, hdr.Gid, "gid of %s", de.Name())
			}
		})
	}
}

// TestLchownTrailingSlash: a trailing slash must not make Lchown resolve the
// link. With /home/link -> /etc and an existing /etc/link, an unclean path
// would otherwise look "link" up in the link's target and re-own /etc/link.
func TestLchownTrailingSlash(t *testing.T) {
	for name, newFS := range map[string]func(t *testing.T) FullFS{
		"memfs": func(*testing.T) FullFS { return NewMemFS() },
		"dirfs": func(t *testing.T) FullFS { return DirFS(t.Context(), t.TempDir()) },
	} {
		t.Run(name, func(t *testing.T) {
			fsys := newFS(t)
			require.NoError(t, fsys.MkdirAll("/etc", 0o755))
			require.NoError(t, fsys.WriteFile("/etc/link", []byte("x"), 0o644))
			require.NoError(t, fsys.MkdirAll("/home", 0o755))
			require.NoError(t, fsys.Symlink("/etc", "/home/link"))

			require.NoError(t, fsys.(LchownFS).Lchown("/home/link/", 999, 998))

			fi, err := fsys.Stat("/etc/link")
			require.NoError(t, err)
			require.Equal(t, 0, fi.Sys().(*tar.Header).Uid, "/etc/link was re-owned")
			des, err := fsys.ReadDir("/home")
			require.NoError(t, err)
			require.Len(t, des, 1)
			info, err := des[0].Info()
			require.NoError(t, err)
			require.Equal(t, 999, info.Sys().(*tar.Header).Uid, "/home/link was not re-owned")
			require.Equal(t, 998, info.Sys().(*tar.Header).Gid, "/home/link was not re-owned")
		})
	}
}

// noLchownFS hides any Lchown method of the wrapped filesystem.
type noLchownFS struct{ FullFS }

func TestSubFSLchownUnsupported(t *testing.T) {
	base := noLchownFS{NewMemFS()}
	require.NoError(t, base.MkdirAll("/sub/home", 0o755))
	require.NoError(t, base.Symlink("/etc", "/sub/home/link"))
	sub := &SubFS{FS: base, Root: "/sub"}
	require.ErrorIs(t, sub.Lchown("/home/link", 999, 998), errors.ErrUnsupported)

	full := &SubFS{FS: NewMemFS(), Root: "/sub"}
	require.NoError(t, full.FS.MkdirAll("/sub/home", 0o755))
	require.NoError(t, full.FS.Symlink("/etc", "/sub/home/link"))
	require.NoError(t, full.Lchown("/home/link", 999, 998))
}
