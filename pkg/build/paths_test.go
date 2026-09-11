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
	"bytes"
	"context"
	"io/fs"
	"testing"

	"github.com/stretchr/testify/require"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/build/types"
)

func TestMutateDirectorySpecialBits(t *testing.T) {
	for _, test := range []struct {
		desc         string
		permissions  uint32
		expectedMode fs.FileMode
	}{
		{
			desc:         "plain permissions",
			permissions:  0o755,
			expectedMode: 0o755,
		},
		{
			desc:         "setgid",
			permissions:  0o2775,
			expectedMode: 0o775 | fs.ModeSetgid,
		},
		{
			desc:         "setuid",
			permissions:  0o4755,
			expectedMode: 0o755 | fs.ModeSetuid,
		},
		{
			desc:         "sticky",
			permissions:  0o1777,
			expectedMode: 0o777 | fs.ModeSticky,
		},
		{
			desc:         "all special bits",
			permissions:  0o7775,
			expectedMode: 0o775 | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky,
		},
		{
			desc: "bits above 0o7777 are dropped, not misinterpreted",
			// 1<<22 is fs.ModeSetgid; passing it raw must not smuggle in
			// setgid (or any other fs.FileMode flag).
			permissions:  1<<22 | 0o755,
			expectedMode: 0o755,
		},
		{
			desc: "decimal-vs-octal typo only yields its actual mode bits",
			// "permissions: 775" (decimal, missing 0o) = 0o1407: sticky + 407.
			permissions:  775,
			expectedMode: 0o407 | fs.ModeSticky,
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			fsys := apkfs.NewMemFS()
			mut := types.PathMutation{
				Path:        "/var/log/kolla",
				Type:        "directory",
				Permissions: test.permissions,
			}
			require.NoError(t, mutateDirectory(fsys, nil, mut))
			// mutatePaths follows up non-permissions mutations with
			// mutatePermissions; exercise that path too.
			require.NoError(t, mutatePermissions(fsys, nil, mut))

			fi, err := fsys.Stat("/var/log/kolla")
			require.NoError(t, err)
			require.Equal(t, test.expectedMode, fi.Mode().Perm()|fi.Mode()&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky))
		})
	}
}

func TestMutateDirectoryRecursiveSpecialBits(t *testing.T) {
	fsys := apkfs.NewMemFS()
	require.NoError(t, fsys.MkdirAll("/var/log/kolla/glance", 0o755))

	// mutateDirectory only creates the tree; mutatePaths runs the recursive
	// permissions follow-up, so exercise the full pipeline.
	ic := &types.ImageConfiguration{Paths: []types.PathMutation{{
		Path:        "/var/log/kolla",
		Type:        "directory",
		Permissions: 0o2775,
		Recursive:   true,
	}}}
	require.NoError(t, mutatePaths(fsys, nil, ic))

	for _, path := range []string{"/var/log/kolla", "/var/log/kolla/glance"} {
		fi, err := fsys.Stat(path)
		require.NoError(t, err)
		require.Equal(t, fs.ModeSetgid, fi.Mode()&fs.ModeSetgid, "setgid missing on %s", path)
		require.Equal(t, fs.FileMode(0o775), fi.Mode().Perm(), "perms wrong on %s", path)
	}
}

func TestMutatePermissionsMissingPath(t *testing.T) {
	fsys := apkfs.NewMemFS()
	require.Error(t, mutatePermissionsDirect(fsys, "/does/not/exist", 0o2775, nil, nil))
}

// TestMutatePermissionsRecursive applies a "permissions" mutation recursively
// over a pre-existing tree and asserts perms + ownership reach every entry.
func TestMutatePermissionsRecursive(t *testing.T) {
	fsys := apkfs.NewMemFS()
	require.NoError(t, fsys.MkdirAll("/srv/data/sub", 0o700))
	f, err := fsys.Create("/srv/data/sub/file")
	require.NoError(t, err)
	require.NoError(t, f.Close())

	ic := &types.ImageConfiguration{Paths: []types.PathMutation{{
		Path:        "/srv/data",
		Type:        "permissions",
		Permissions: 0o2750,
		UID:         new(uint32(64045)),
		GID:         new(uint32(64045)),
		Recursive:   true,
	}}}
	require.NoError(t, mutatePaths(fsys, nil, ic))

	for _, path := range []string{"/srv/data", "/srv/data/sub", "/srv/data/sub/file"} {
		fi, err := fsys.Stat(path)
		require.NoError(t, err)
		require.Equal(t, fs.FileMode(0o750), fi.Mode().Perm(), "perms wrong on %s", path)
		require.Equal(t, fs.ModeSetgid, fi.Mode()&fs.ModeSetgid, "setgid missing on %s", path)
		require.Equal(t, 64045, fileUID(t, fsys, path), "uid wrong on %s", path)
		require.Equal(t, 64045, fileGID(t, fsys, path), "gid wrong on %s", path)
	}
}

// fileUID/fileGID read ownership from the memfs FileInfo, whose Sys() returns a
// *tar.Header carrying Uid/Gid.
func fileUID(t *testing.T, fsys apkfs.FullFS, path string) int {
	t.Helper()
	fi, err := fsys.Stat(path)
	require.NoError(t, err)
	hdr, ok := fi.Sys().(*tar.Header)
	require.True(t, ok, "unexpected FileInfo.Sys() type for %s", path)
	return hdr.Uid
}

func fileGID(t *testing.T, fsys apkfs.FullFS, path string) int {
	t.Helper()
	fi, err := fsys.Stat(path)
	require.NoError(t, err)
	hdr, ok := fi.Sys().(*tar.Header)
	require.True(t, ok, "unexpected FileInfo.Sys() type for %s", path)
	return hdr.Gid
}

// TestMutatePermissionsRecursiveModeOnly verifies that omitting uid/gid leaves
// ownership untouched while still applying the mode recursively.
func TestMutatePermissionsRecursiveModeOnly(t *testing.T) {
	fsys := apkfs.NewMemFS()
	require.NoError(t, fsys.MkdirAll("/srv/data/sub", 0o700))
	require.NoError(t, fsys.Chown("/srv/data", 1000, 1000))
	require.NoError(t, fsys.Chown("/srv/data/sub", 1000, 1000))

	ic := &types.ImageConfiguration{Paths: []types.PathMutation{{
		Path:        "/srv/data",
		Type:        "permissions",
		Permissions: 0o755,
		Recursive:   true,
	}}}
	require.NoError(t, mutatePaths(fsys, nil, ic))

	for _, path := range []string{"/srv/data", "/srv/data/sub"} {
		fi, err := fsys.Stat(path)
		require.NoError(t, err)
		require.Equal(t, fs.FileMode(0o755), fi.Mode().Perm(), "perms wrong on %s", path)
		// Ownership must be left as-is (1000:1000), not reset to root.
		require.Equal(t, 1000, fileUID(t, fsys, path), "ownership changed on %s", path)
	}
}

// TestMutatePermissionsRecursiveOnFile applies a recursive "permissions"
// mutation to a single regular file: it must affect just that file, no error.
func TestMutatePermissionsRecursiveOnFile(t *testing.T) {
	fsys := apkfs.NewMemFS()
	require.NoError(t, fsys.MkdirAll("/usr/bin", 0o755))
	f, err := fsys.Create("/usr/bin/tool")
	require.NoError(t, err)
	require.NoError(t, f.Close())

	require.NoError(t, mutatePermissionsRecursive(fsys, "/usr/bin/tool", 0o4755, new(uint32(0)), new(uint32(0))))

	fi, err := fsys.Stat("/usr/bin/tool")
	require.NoError(t, err)
	require.Equal(t, fs.ModeSetuid, fi.Mode()&fs.ModeSetuid)
	require.Equal(t, fs.FileMode(0o755), fi.Mode().Perm())
}

func TestMutatePermissionsRecursiveMissingPath(t *testing.T) {
	fsys := apkfs.NewMemFS()
	require.Error(t, mutatePermissionsRecursive(fsys, "/does/not/exist", 0o755, nil, nil))
}

// TestMutatePermissionsNonRecursiveDoesNotRecurse guards the original bug: a
// non-recursive "permissions" mutation must touch only the named path, never
// its children.
func TestMutatePermissionsNonRecursiveDoesNotRecurse(t *testing.T) {
	fsys := apkfs.NewMemFS()
	require.NoError(t, fsys.MkdirAll("/srv/data/sub", 0o700))

	ic := &types.ImageConfiguration{Paths: []types.PathMutation{{
		Path:        "/srv/data",
		Type:        "permissions",
		Permissions: 0o755,
		// Recursive intentionally omitted (false).
	}}}
	require.NoError(t, mutatePaths(fsys, nil, ic))

	top, err := fsys.Stat("/srv/data")
	require.NoError(t, err)
	require.Equal(t, fs.FileMode(0o755), top.Mode().Perm(), "top path should change")

	child, err := fsys.Stat("/srv/data/sub")
	require.NoError(t, err)
	require.Equal(t, fs.FileMode(0o700), child.Mode().Perm(), "child must be untouched without recursive")
}

// TestMutatePermissionsExplicitZeroResetsOwnership verifies an explicit
// uid:0/gid:0 (non-nil) resets ownership, distinct from omitting them (which
// leaves it untouched, see TestMutatePermissionsRecursiveModeOnly). This is the
// core distinction the nullable uid/gid type enables.
func TestMutatePermissionsExplicitZeroResetsOwnership(t *testing.T) {
	fsys := apkfs.NewMemFS()
	require.NoError(t, fsys.MkdirAll("/srv/data", 0o755))
	require.NoError(t, fsys.Chown("/srv/data", 1000, 1000))

	require.NoError(t, mutatePermissionsDirect(fsys, "/srv/data", 0o755, new(uint32(0)), new(uint32(0))))

	require.Equal(t, 0, fileUID(t, fsys, "/srv/data"), "explicit uid:0 must reset owner to root")
	require.Equal(t, 0, fileGID(t, fsys, "/srv/data"), "explicit gid:0 must reset group to root")
}

// TestMutatePermissionsOneOwnerDefaultsOtherToZero verifies that setting only
// one of uid/gid defaults the other to 0 (root), preserving historical behavior.
func TestMutatePermissionsOneOwnerDefaultsOtherToZero(t *testing.T) {
	fsys := apkfs.NewMemFS()
	require.NoError(t, fsys.MkdirAll("/srv/data", 0o755))

	// uid set, gid omitted -> gid defaults to 0.
	require.NoError(t, fsys.Chown("/srv/data", 1000, 1000))
	require.NoError(t, mutatePermissionsDirect(fsys, "/srv/data", 0o755, new(uint32(42)), nil))
	require.Equal(t, 42, fileUID(t, fsys, "/srv/data"))
	require.Equal(t, 0, fileGID(t, fsys, "/srv/data"))

	// gid set, uid omitted -> uid defaults to 0.
	require.NoError(t, fsys.Chown("/srv/data", 1000, 1000))
	require.NoError(t, mutatePermissionsDirect(fsys, "/srv/data", 0o755, nil, new(uint32(7))))
	require.Equal(t, 0, fileUID(t, fsys, "/srv/data"))
	require.Equal(t, 7, fileGID(t, fsys, "/srv/data"))
}

// TestMutatePermissionsRecursiveWithSymlink ensures a symlink inside the tree
// does not abort the recursive walk (WalkDir does not follow symlinks) and that
// regular entries are still mutated.
func TestMutatePermissionsRecursiveWithSymlink(t *testing.T) {
	fsys := apkfs.NewMemFS()
	require.NoError(t, fsys.MkdirAll("/srv/data", 0o700))
	f, err := fsys.Create("/srv/data/real")
	require.NoError(t, err)
	require.NoError(t, f.Close())
	require.NoError(t, fsys.Symlink("/srv/data/real", "/srv/data/link"))

	ic := &types.ImageConfiguration{Paths: []types.PathMutation{{
		Path:        "/srv/data",
		Type:        "permissions",
		Permissions: 0o750,
		Recursive:   true,
	}}}
	require.NoError(t, mutatePaths(fsys, nil, ic))

	fi, err := fsys.Stat("/srv/data/real")
	require.NoError(t, err)
	require.Equal(t, fs.FileMode(0o750), fi.Mode().Perm(), "regular file in tree must be mutated")
}

// TestPathMutationSpecialBitsReachTar covers the full chain: paths mutation →
// FS → tar header. This is where the dropped bits were observable in images.
func TestPathMutationSpecialBitsReachTar(t *testing.T) {
	fsys := apkfs.NewMemFS()
	ic := &types.ImageConfiguration{
		Paths: []types.PathMutation{{
			Path:        "var",
			Type:        "directory",
			Permissions: 0o755,
		}, {
			Path:        "var/log",
			Type:        "directory",
			Permissions: 0o755,
		}, {
			Path:        "var/log/kolla",
			Type:        "directory",
			Permissions: 0o2775,
			UID:         new(uint32(0)),
			GID:         new(uint32(42400)),
		}},
	}
	require.NoError(t, mutatePaths(fsys, nil, ic))

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	require.NoError(t, writeTar(context.Background(), tw, fsys))
	require.NoError(t, tw.Close())

	tr := tar.NewReader(&buf)
	for {
		hdr, err := tr.Next()
		require.NoError(t, err, "tar must contain var/log/kolla")
		if hdr.Name != "var/log/kolla" {
			continue
		}
		require.Equal(t, int64(0o2775), hdr.Mode&0o7777, "tar header mode")
		require.Equal(t, fs.ModeSetgid, hdr.FileInfo().Mode()&fs.ModeSetgid)
		require.Equal(t, 42400, hdr.Gid)
		return
	}
}

func TestMutatePermissionsSpecialBitsOnFile(t *testing.T) {
	fsys := apkfs.NewMemFS()
	require.NoError(t, fsys.MkdirAll("/usr/bin", 0o755))
	f, err := fsys.Create("/usr/bin/suidtool")
	require.NoError(t, err)
	require.NoError(t, f.Close())

	require.NoError(t, mutatePermissionsDirect(fsys, "/usr/bin/suidtool", 0o4755, new(uint32(0)), new(uint32(0))))

	fi, err := fsys.Stat("/usr/bin/suidtool")
	require.NoError(t, err)
	require.Equal(t, fs.ModeSetuid, fi.Mode()&fs.ModeSetuid)
	require.Equal(t, fs.FileMode(0o755), fi.Mode().Perm())
}
