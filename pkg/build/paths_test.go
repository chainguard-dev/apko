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
	"io/fs"
	"testing"

	"github.com/stretchr/testify/require"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/options"
)

func TestMutatePathsSymlinkAllowsMissingTarget(t *testing.T) {
	fsys := apkfs.NewMemFS()

	err := mutatePaths(fsys, &options.Default, &types.ImageConfiguration{
		Paths: []types.PathMutation{{
			Path:   "/bin/xyz",
			Type:   "symlink",
			Source: "/ko-app/abc",
		}},
	})
	require.NoError(t, err)

	target, err := fsys.Readlink("/bin/xyz")
	require.NoError(t, err)
	require.Equal(t, "/ko-app/abc", target)
}

func TestMutatePathsSymlinkDoesNotChangeTargetPermissions(t *testing.T) {
	fsys := apkfs.NewMemFS()
	require.NoError(t, fsys.MkdirAll("/var/lib/foo", 0o755))

	err := mutatePaths(fsys, &options.Default, &types.ImageConfiguration{
		Paths: []types.PathMutation{{
			Path:   "/foo",
			Type:   "symlink",
			Source: "/var/lib/foo",
		}},
	})
	require.NoError(t, err)

	target, err := fsys.Readlink("/foo")
	require.NoError(t, err)
	require.Equal(t, "/var/lib/foo", target)

	info, err := fsys.Stat("/var/lib/foo")
	require.NoError(t, err)
	require.Equal(t, fs.FileMode(0o755), info.Mode().Perm())
}

func TestMutateDirectoryRecursiveSkipsSymlinks(t *testing.T) {
	fsys := apkfs.NewMemFS()
	require.NoError(t, fsys.MkdirAll("/tree/target", 0o755))
	require.NoError(t, fsys.Symlink("/missing", "/tree/link"))

	err := mutatePaths(fsys, &options.Default, &types.ImageConfiguration{
		Paths: []types.PathMutation{{
			Path:        "/tree",
			Type:        "directory",
			Permissions: 0o700,
			Recursive:   true,
		}},
	})
	require.NoError(t, err)

	target, err := fsys.Readlink("/tree/link")
	require.NoError(t, err)
	require.Equal(t, "/missing", target)

	info, err := fsys.Stat("/tree/target")
	require.NoError(t, err)
	require.Equal(t, fs.FileMode(0o700), info.Mode().Perm())
}
