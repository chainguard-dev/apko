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

	mut := types.PathMutation{
		Path:        "/var/log/kolla",
		Type:        "directory",
		Permissions: 0o2775,
		Recursive:   true,
	}
	require.NoError(t, mutateDirectory(fsys, nil, mut))

	for _, path := range []string{"/var/log/kolla", "/var/log/kolla/glance"} {
		fi, err := fsys.Stat(path)
		require.NoError(t, err)
		require.Equal(t, fs.ModeSetgid, fi.Mode()&fs.ModeSetgid, "setgid missing on %s", path)
		require.Equal(t, fs.FileMode(0o775), fi.Mode().Perm(), "perms wrong on %s", path)
	}
}

func TestMutatePermissionsMissingPath(t *testing.T) {
	fsys := apkfs.NewMemFS()
	require.Error(t, mutatePermissionsDirect(fsys, "/does/not/exist", 0o2775, 0, 0))
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
			UID:         0,
			GID:         42400,
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

	require.NoError(t, mutatePermissionsDirect(fsys, "/usr/bin/suidtool", 0o4755, 0, 0))

	fi, err := fsys.Stat("/usr/bin/suidtool")
	require.NoError(t, err)
	require.Equal(t, fs.ModeSetuid, fi.Mode()&fs.ModeSetuid)
	require.Equal(t, fs.FileMode(0o755), fi.Mode().Perm())
}
