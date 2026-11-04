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
	"crypto/sha1" //nolint:gosec // APK per-file checksums are SHA-1
	"encoding/hex"
	"io/fs"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/apk/apk"
	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/tarfs"
)

// symlinkTestFSes covers the generic memfs, the tarfs that image builds run
// path mutations against, and the dirFS that build-cpio uses.
var symlinkTestFSes = map[string]func(t *testing.T) apkfs.FullFS{
	"memfs": func(*testing.T) apkfs.FullFS { return apkfs.NewMemFS() },
	"tarfs": func(*testing.T) apkfs.FullFS { return tarfs.New() },
	"dirfs": func(t *testing.T) apkfs.FullFS { return apkfs.DirFS(t.Context(), t.TempDir()) },
}

// symlinkOwnerCases covers each combination of uid/gid being set. Entries
// start out owned by 1234:1235 so that "neither" can tell a kept owner apart
// from a reset to root.
var symlinkOwnerCases = []struct {
	name             string
	uid              types.UID
	gid              types.GID
	wantUID, wantGID int
}{
	{name: "uid+gid", uid: new(uint32(999)), gid: new(uint32(998)), wantUID: 999, wantGID: 998},
	{name: "uid only", uid: new(uint32(999)), wantUID: 999, wantGID: 0},
	{name: "gid only", gid: new(uint32(998)), wantUID: 0, wantGID: 998},
	{name: "neither", wantUID: 1234, wantGID: 1235},
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
//
// On dirFS, chmod of such a link used to fail the build outright: *os.Root
// resolves the absolute target against the host and refuses with "path
// escapes from parent", whether or not uid/gid are set.
func TestMutatePermissionsRecursiveDoesNotFollowSymlinks(t *testing.T) {
	links := []string{
		"/home/app/venv/lib/certifi/cacert.pem",
		"/home/app/venv/lib/certifi/passwd",
		"/home/app/etc",
	}
	for name, newFS := range symlinkTestFSes {
		for _, typ := range []string{"directory", "permissions"} {
			for _, owner := range symlinkOwnerCases {
				t.Run(name+"/"+typ+"/"+owner.name, func(t *testing.T) {
					fsys := newFS(t)

					// Files outside the tree, owned by root.
					require.NoError(t, fsys.MkdirAll("/etc/ssl/certs", 0o755))
					require.NoError(t, fsys.WriteFile("/etc/ssl/certs/ca-certificates.crt", []byte("certs"), 0o644))
					require.NoError(t, fsys.WriteFile("/etc/passwd", []byte("root"), 0o644))

					// The tree being mutated, with an absolute link, a relative
					// link escaping via "..", and a link to a directory outside
					// the tree.
					venv := "/home/app/venv/lib/certifi"
					require.NoError(t, fsys.MkdirAll(venv, 0o755))
					require.NoError(t, fsys.Symlink("/etc/ssl/certs/ca-certificates.crt", links[0]))
					require.NoError(t, fsys.Symlink("../../../../../etc/passwd", links[1]))
					require.NoError(t, fsys.Symlink("/etc", links[2]))

					require.NoError(t, fsys.Chown(venv, 1234, 1235))
					lfs, ok := fsys.(apkfs.LchownFS)
					require.True(t, ok)
					for _, link := range links {
						require.NoError(t, lfs.Lchown(link, 1234, 1235))
					}

					ic := &types.ImageConfiguration{Paths: []types.PathMutation{{
						Path:        "/home/app",
						Type:        typ,
						Permissions: 0o775,
						UID:         owner.uid,
						GID:         owner.gid,
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
					require.Equal(t, owner.wantUID, fileUID(t, fsys, venv))
					require.Equal(t, owner.wantGID, fileGID(t, fsys, venv))

					// The links are still links, and carry the requested owner.
					for _, link := range links {
						typ, hdr := entryHeader(t, fsys, link)
						require.NotZero(t, typ&fs.ModeSymlink, "%s is no longer a symlink", link)
						require.Equal(t, owner.wantUID, hdr.Uid, "uid of link %s", link)
						require.Equal(t, owner.wantGID, hdr.Gid, "gid of link %s", link)
					}
				})
			}
		}
	}
}

// TestMutatePermissionsRecursiveDanglingSymlink: a dangling symlink inside
// the tree must not fail the build (chown -R/chmod -R do not care either).
func TestMutatePermissionsRecursiveDanglingSymlink(t *testing.T) {
	for name, newFS := range symlinkTestFSes {
		t.Run(name, func(t *testing.T) {
			fsys := newFS(t)
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
			fsys := newFS(t)
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

// TestMutatePermissionsRecursiveSymlinkPathIsFollowed pins that a symlink
// given as the mutation path is resolved for ownership as well as mode, so a
// compat path such as /opt/<app> linking to the package's real tree re-owns
// that tree (chmod -R plus chown -R -H, not plain chown -R). The link is
// relative because dirFS resolves an absolute one against the host.
func TestMutatePermissionsRecursiveSymlinkPathIsFollowed(t *testing.T) {
	for name, newFS := range symlinkTestFSes {
		t.Run(name, func(t *testing.T) {
			fsys := newFS(t)
			require.NoError(t, fsys.MkdirAll("/usr/share/java/app/lib", 0o755))
			require.NoError(t, fsys.WriteFile("/usr/share/java/app/lib/app.jar", []byte("jar"), 0o644))
			require.NoError(t, fsys.MkdirAll("/opt", 0o755))
			require.NoError(t, fsys.Symlink("../usr/share/java/app", "/opt/app"))

			ic := &types.ImageConfiguration{Paths: []types.PathMutation{{
				Path:        "/opt/app",
				Type:        "permissions",
				Permissions: 0o750,
				UID:         new(uint32(999)),
				GID:         new(uint32(998)),
				Recursive:   true,
			}}}
			require.NoError(t, mutatePaths(fsys, nil, ic))

			for _, path := range []string{
				"/usr/share/java/app",
				"/usr/share/java/app/lib",
				"/usr/share/java/app/lib/app.jar",
			} {
				fi, err := fsys.Stat(path)
				require.NoError(t, err)
				require.Equal(t, fs.FileMode(0o750), fi.Mode().Perm(), "mode of %s", path)
				require.Equal(t, 999, fileUID(t, fsys, path), "uid of %s", path)
				require.Equal(t, 998, fileGID(t, fsys, path), "gid of %s", path)
			}

			// The walk starts at the link's target: nothing above it changes.
			fi, err := fsys.Stat("/usr/share/java")
			require.NoError(t, err)
			require.Equal(t, fs.FileMode(0o755), fi.Mode().Perm())
			require.Equal(t, 0, fileUID(t, fsys, "/usr/share/java"))
		})
	}
}

// TestMutatePermissionsRecursiveTarFSPackageSymlinks installs the tree through
// tarfs WriteHeader, the way package installation populates an image, rather
// than through Symlink, and then runs the recursive mutation over it.
func TestMutatePermissionsRecursiveTarFSPackageSymlinks(t *testing.T) {
	sum := func(b []byte) map[string]string {
		s := sha1.Sum(b) //nolint:gosec // APK per-file checksums are SHA-1
		return map[string]string{"APK-TOOLS.checksum.SHA1": hex.EncodeToString(s[:])}
	}
	certs, python := []byte("certs"), []byte("python")
	src := fstest.MapFS{
		"etc/ssl/certs/ca-certificates.crt": {Data: certs, Mode: 0o644},
		"usr/bin/python3.12":                {Data: python, Mode: 0o755},
	}
	dir := func(name string, mode int64) tar.Header {
		return tar.Header{Typeflag: tar.TypeDir, Name: name, Mode: mode}
	}
	reg := func(name string, mode int64, data []byte) tar.Header {
		return tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: mode, Size: int64(len(data)), PAXRecords: sum(data)}
	}
	symlink := func(name, target string) tar.Header {
		return tar.Header{Typeflag: tar.TypeSymlink, Name: name, Linkname: target, Mode: 0o777, PAXRecords: sum([]byte(target))}
	}
	system := []tar.Header{
		dir("etc", 0o755), dir("etc/ssl", 0o755), dir("etc/ssl/certs", 0o755),
		reg("etc/ssl/certs/ca-certificates.crt", 0o644, certs),
		dir("usr", 0o755), dir("usr/bin", 0o755),
		reg("usr/bin/python3.12", 0o755, python),
	}
	app := []tar.Header{
		dir("home", 0o755), dir("home/app", 0o755), dir("home/app/venv", 0o755),
		dir("home/app/venv/bin", 0o755), dir("home/app/venv/lib", 0o755),
		dir("home/app/venv/lib/certifi", 0o755),
		symlink("home/app/venv/lib/certifi/cacert.pem", "/etc/ssl/certs/ca-certificates.crt"),
		symlink("home/app/venv/bin/python", "/usr/bin/python3.12"),
	}

	for _, typ := range []string{"directory", "permissions"} {
		t.Run(typ, func(t *testing.T) {
			fsys := tarfs.New()
			for _, pkg := range []struct {
				name string
				hdrs []tar.Header
			}{{"system", system}, {"app", app}} {
				for _, hdr := range pkg.hdrs {
					_, err := fsys.WriteHeader(hdr, src, &apk.Package{Name: pkg.name, Origin: pkg.name})
					require.NoError(t, err, "installing %s", hdr.Name)
				}
			}

			ic := &types.ImageConfiguration{Paths: []types.PathMutation{{
				Path:        "/home/app",
				Type:        typ,
				Permissions: 0o775,
				UID:         new(uint32(999)),
				GID:         new(uint32(998)),
				Recursive:   true,
			}}}
			require.NoError(t, mutatePaths(fsys, nil, ic))

			for path, wantMode := range map[string]fs.FileMode{
				"/etc/ssl/certs/ca-certificates.crt": 0o644,
				"/usr/bin/python3.12":                0o755,
			} {
				fi, err := fsys.Stat(path)
				require.NoError(t, err)
				require.Equal(t, wantMode, fi.Mode().Perm(), "mode of %s outside the tree changed", path)
				require.Equal(t, 0, fileUID(t, fsys, path), "uid of %s outside the tree changed", path)
				require.Equal(t, 0, fileGID(t, fsys, path), "gid of %s outside the tree changed", path)
			}

			require.Equal(t, 999, fileUID(t, fsys, "/home/app/venv/lib/certifi"))
			for link, target := range map[string]string{
				"/home/app/venv/lib/certifi/cacert.pem": "/etc/ssl/certs/ca-certificates.crt",
				"/home/app/venv/bin/python":             "/usr/bin/python3.12",
			} {
				typ, hdr := entryHeader(t, fsys, link)
				require.NotZero(t, typ&fs.ModeSymlink, "%s is no longer a symlink", link)
				require.Equal(t, 999, hdr.Uid, "uid of link %s", link)
				require.Equal(t, 998, hdr.Gid, "gid of link %s", link)
				got, err := fsys.Readlink(link)
				require.NoError(t, err)
				require.Equal(t, target, got)
			}
		})
	}
}

// noLchownFS hides any Lchown method of the wrapped filesystem.
type noLchownFS struct{ apkfs.FullFS }

// TestMutatePermissionsRecursiveSubFSWithoutLchown: SubFS always has Lchown,
// but over a filesystem without it, it reports errors.ErrUnsupported. The walk
// must treat that like a filesystem without Lchown, leaving the link's owner
// alone instead of failing the build.
func TestMutatePermissionsRecursiveSubFSWithoutLchown(t *testing.T) {
	base := noLchownFS{apkfs.NewMemFS()}
	_, ok := apkfs.FullFS(base).(apkfs.LchownFS)
	require.False(t, ok, "noLchownFS must not implement LchownFS")

	require.NoError(t, base.MkdirAll("/sub/home/app/lib", 0o700))
	require.NoError(t, base.Symlink("/etc/missing", "/sub/home/app/lib/link"))
	sub := &apkfs.SubFS{FS: base, Root: "/sub"}

	ic := &types.ImageConfiguration{Paths: []types.PathMutation{{
		Path:        "/home/app",
		Type:        "permissions",
		Permissions: 0o755,
		UID:         new(uint32(999)),
		GID:         new(uint32(998)),
		Recursive:   true,
	}}}
	require.NoError(t, mutatePaths(sub, nil, ic))

	require.Equal(t, 999, fileUID(t, base, "/sub/home/app/lib"))
	_, hdr := entryHeader(t, base, "/sub/home/app/lib/link")
	require.Equal(t, 0, hdr.Uid, "link owner should be left alone")
	require.Equal(t, 0, hdr.Gid, "link owner should be left alone")
}
