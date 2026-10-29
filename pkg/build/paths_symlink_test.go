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

package build

import (
	"archive/tar"
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/tarfs"
)

// symlinkTestFSes covers the generic memfs and the tarfs that image builds
// actually run path mutations against.
var symlinkTestFSes = map[string]func() apkfs.FullFS{
	"memfs": apkfs.NewMemFS,
	"tarfs": func() apkfs.FullFS { return tarfs.New() },
}

// entryHeader returns the type and owner header of the directory entry itself
// (the symlink node, not its target), read through the parent's ReadDir.
func entryHeader(t *testing.T, fsys apkfs.FullFS, path string) (fs.FileMode, *tar.Header) {
	t.Helper()
	des, err := fsys.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	for _, de := range des {
		if de.Name() != filepath.Base(path) {
			continue
		}
		fi, err := de.Info()
		require.NoError(t, err)
		hdr, ok := fi.Sys().(*tar.Header)
		require.True(t, ok, "unexpected FileInfo.Sys() type for %s", path)
		return de.Type(), hdr
	}
	t.Fatalf("entry %s not found", path)
	return 0, nil
}

// TestMutatePermissionsRecursiveDoesNotFollowSymlinks reproduces a recursive
// path mutation over a directory that contains symlinks pointing outside it
// (e.g. a Python venv whose certifi/cacert.pem links to the system CA bundle).
// The mutation must not change the mode or ownership of anything outside the
// tree; the links themselves take the requested ownership, as `chown -R` does.
func TestMutatePermissionsRecursiveDoesNotFollowSymlinks(t *testing.T) {
	for name, newFS := range symlinkTestFSes {
		for _, typ := range []string{"directory", "permissions"} {
			t.Run(name+"/"+typ, func(t *testing.T) {
				fsys := newFS()

				// Files outside the tree, owned by root.
				require.NoError(t, fsys.MkdirAll("/etc/ssl/certs", 0o755))
				require.NoError(t, fsys.WriteFile("/etc/ssl/certs/ca-certificates.crt", []byte("certs"), 0o644))
				require.NoError(t, fsys.WriteFile("/etc/passwd", []byte("root"), 0o644))

				// The tree being mutated, with an absolute link, a relative
				// link escaping via "..", and a link to a directory outside
				// the tree.
				venv := "/home/app/venv/lib/certifi"
				require.NoError(t, fsys.MkdirAll(venv, 0o755))
				require.NoError(t, fsys.Symlink("/etc/ssl/certs/ca-certificates.crt", venv+"/cacert.pem"))
				require.NoError(t, fsys.Symlink("../../../../../etc/passwd", venv+"/passwd"))
				require.NoError(t, fsys.Symlink("/etc", "/home/app/etc"))

				ic := &types.ImageConfiguration{Paths: []types.PathMutation{{
					Path:        "/home/app",
					Type:        typ,
					Permissions: 0o775,
					UID:         new(uint32(999)),
					GID:         new(uint32(999)),
					Recursive:   true,
				}}}
				require.NoError(t, mutatePaths(fsys, nil, ic))

				for path, wantMode := range map[string]fs.FileMode{
					"/etc/ssl/certs/ca-certificates.crt": 0o644,
					"/etc/passwd":                        0o644,
					"/etc":                               0o755,
				} {
					fi, err := fsys.Stat(path)
					require.NoError(t, err)
					require.Equal(t, wantMode, fi.Mode().Perm(), "mode of %s outside the tree changed", path)
					require.Equal(t, 0, fileUID(t, fsys, path), "uid of %s outside the tree changed", path)
					require.Equal(t, 0, fileGID(t, fsys, path), "gid of %s outside the tree changed", path)
				}

				// Regular entries inside the tree are still mutated.
				fi, err := fsys.Stat(venv)
				require.NoError(t, err)
				require.Equal(t, fs.FileMode(0o775), fi.Mode().Perm())
				require.Equal(t, 999, fileUID(t, fsys, venv))

				// The links are still links, and carry the requested owner.
				for _, link := range []string{venv + "/cacert.pem", venv + "/passwd", "/home/app/etc"} {
					typ, hdr := entryHeader(t, fsys, link)
					require.NotZero(t, typ&fs.ModeSymlink, "%s is no longer a symlink", link)
					require.Equal(t, 999, hdr.Uid, "uid of link %s", link)
					require.Equal(t, 999, hdr.Gid, "gid of link %s", link)
				}
			})
		}
	}
}

// TestMutatePermissionsRecursiveDanglingSymlink: a dangling symlink inside
// the tree must not fail the build (chown -R/chmod -R do not care either).
func TestMutatePermissionsRecursiveDanglingSymlink(t *testing.T) {
	for name, newFS := range symlinkTestFSes {
		t.Run(name, func(t *testing.T) {
			fsys := newFS()
			require.NoError(t, fsys.MkdirAll("/home/app/sub", 0o700))
			require.NoError(t, fsys.Symlink("/does/not/exist", "/home/app/dangling"))

			ic := &types.ImageConfiguration{Paths: []types.PathMutation{{
				Path:        "/home/app",
				Type:        "directory",
				Permissions: 0o755,
				UID:         new(uint32(999)),
				GID:         new(uint32(999)),
				Recursive:   true,
			}}}
			require.NoError(t, mutatePaths(fsys, nil, ic))

			fi, err := fsys.Stat("/home/app/sub")
			require.NoError(t, err)
			require.Equal(t, fs.FileMode(0o755), fi.Mode().Perm())
			target, err := fsys.Readlink("/home/app/dangling")
			require.NoError(t, err)
			require.Equal(t, "/does/not/exist", target)
			_, hdr := entryHeader(t, fsys, "/home/app/dangling")
			require.Equal(t, 999, hdr.Uid)
		})
	}
}

// TestMutatePermissionsNonRecursiveFollowsSymlink keeps the chmod(1)
// semantics for an explicitly named path: a non-recursive "permissions"
// mutation on a symlink applies to its target. This is what per-image
// workarounds such as resetting /etc/ssl/certs/ca-certificates.crt rely on.
func TestMutatePermissionsNonRecursiveFollowsSymlink(t *testing.T) {
	for name, newFS := range symlinkTestFSes {
		t.Run(name, func(t *testing.T) {
			fsys := newFS()
			require.NoError(t, fsys.MkdirAll("/usr/bin", 0o755))
			require.NoError(t, fsys.WriteFile("/usr/bin/python3.12", []byte("py"), 0o775))
			require.NoError(t, fsys.Symlink("python3.12", "/usr/bin/python3"))

			ic := &types.ImageConfiguration{Paths: []types.PathMutation{{
				Path:        "/usr/bin/python3",
				Type:        "permissions",
				Permissions: 0o755,
				UID:         new(uint32(0)),
				GID:         new(uint32(0)),
			}}}
			require.NoError(t, mutatePaths(fsys, nil, ic))

			fi, err := fsys.Stat("/usr/bin/python3.12")
			require.NoError(t, err)
			require.Equal(t, fs.FileMode(0o755), fi.Mode().Perm())
		})
	}
}
