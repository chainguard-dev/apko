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
