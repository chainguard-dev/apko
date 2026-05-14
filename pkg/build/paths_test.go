// paths_test.go
// Copyright 2022, 2023 Chainguard, Inc.
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
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/options"
)

func TestMutatePermissionsDirect(t *testing.T) {
	mfs := apkfs.NewMemFS()

	// Create a file in the memfs.
	filePath := "testfile.txt"
	f, err := mfs.Create(filePath)
	require.NoError(t, err)
	f.Close()

	// Change permissions and ownership.
	err = mutatePermissionsDirect(mfs, filePath, 0644, 1000, 1000)
	require.NoError(t, err)

	// Check file mode.
	info, err := mfs.Stat(filePath)
	require.NoError(t, err)
	require.Equal(t, fs.FileMode(0644), info.Mode().Perm())

	// Note: The in-memory FS may not support ownership checks.
}

// TestMutatePermissionsRecursion verifies that mutatePermissionsDirect recurses
// into directories and updates the permissions of contained files.
func TestMutatePermissionsRecursion(t *testing.T) {
	mfs := apkfs.NewMemFS()

	// Create a directory with a file inside.
	dirPath := "dirRec"
	err := mfs.MkdirAll(dirPath, 0700)
	require.NoError(t, err)
	filePath := filepath.Join(dirPath, "child.txt")
	f, err := mfs.Create(filePath)
	require.NoError(t, err)
	_, err = f.Write([]byte("content"))
	require.NoError(t, err)
	f.Close()

	// Recursively change permissions of the directory and its children.
	err = mutatePermissionsDirect(mfs, dirPath, 0755, 2000, 2000)
	require.NoError(t, err)

	// Check the directory's permissions.
	dirInfo, err := mfs.Stat(dirPath)
	require.NoError(t, err)
	require.Equal(t, fs.FileMode(0755), dirInfo.Mode().Perm())

	// Check the child's permissions.
	childInfo, err := mfs.Stat(filePath)
	require.NoError(t, err)
	require.Equal(t, fs.FileMode(0755), childInfo.Mode().Perm())
}

func TestMutateDirectory(t *testing.T) {
	mfs := apkfs.NewMemFS()
	opts := &options.Options{}

	// Mutation to create a directory.
	mut := types.PathMutation{
		Type:        "directory",
		Path:        "testdir",
		Permissions: 0755,
		UID:         1000,
		GID:         1000,
		Recursive:   false,
	}
	err := mutateDirectory(mfs, opts, mut)
	require.NoError(t, err)

	// Check that the directory exists with the correct permissions.
	info, err := mfs.Stat("testdir")
	require.NoError(t, err)
	require.True(t, info.IsDir())
	require.Equal(t, fs.FileMode(0755), info.Mode().Perm())
}

func TestMutateEmptyFile(t *testing.T) {
	mfs := apkfs.NewMemFS()
	opts := &options.Options{}
	target := filepath.Join("nonexistent", "subdir", "emptyfile.txt")

	mut := types.PathMutation{
		Type: "empty-file",
		Path: target,
	}
	err := mutateEmptyFile(mfs, opts, mut)
	require.NoError(t, err)

	// Verify that the file exists.
	info, err := mfs.Stat(target)
	require.NoError(t, err)
	require.False(t, info.IsDir())
}

func TestMutateHardLink(t *testing.T) {
	mfs := apkfs.NewMemFS()
	opts := &options.Options{}

	// Create a source file.
	src := "source.txt"
	f, err := mfs.Create(src)
	require.NoError(t, err)
	_, err = f.Write([]byte("hello"))
	require.NoError(t, err)
	f.Close()

	target := "hardlink.txt"
	mut := types.PathMutation{
		Type:        "hardlink",
		Path:        target,
		Source:      src,
		Permissions: 0644,
		UID:         1000,
		GID:         1000,
	}
	err = mutateHardLink(mfs, opts, mut)
	require.NoError(t, err)

	// Verify that the target file exists and has the same content.
	data, err := mfs.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), data)
}

func TestMutateSymLink(t *testing.T) {
	mfs := apkfs.NewMemFS()
	opts := &options.Options{}

	// Create a target directory to link to.
	src := "real_target"
	err := mfs.MkdirAll(src, 0755)
	require.NoError(t, err)

	target := "symlink.txt"
	mut := types.PathMutation{
		Type:        "symlink",
		Path:        target,
		Source:      src,
		Permissions: 0777, // permissions here will be applied to the target of the symlink
		UID:         1000,
		GID:         1000,
	}
	err = mutateSymLink(mfs, opts, mut)
	require.NoError(t, err)

	// Verify that the symlink still points to the correct source.
	linkTarget, err := mfs.Readlink(target)
	require.NoError(t, err)
	require.Equal(t, src, linkTarget)
}

func TestMutatePaths(t *testing.T) {
	mfs := apkfs.NewMemFS()
	opts := &options.Options{}

	ic := &types.ImageConfiguration{
		Paths: []types.PathMutation{
			{
				Type:        "directory",
				Path:        "dir1",
				Permissions: 0755,
				UID:         1000,
				GID:         1000,
			},
			{
				Type: "empty-file",
				Path: "dir1/empty.txt",
			},
			{
				Type:        "hardlink",
				Path:        "hardlink.txt",
				Source:      "dir1/empty.txt",
				Permissions: 0644,
				UID:         1000,
				GID:         1000,
			},
			{
				Type:        "symlink",
				Path:        "symlink.txt",
				Source:      "dir1",
				Permissions: 0777,
				UID:         1000,
				GID:         1000,
			},
			{
				Type:        "permissions",
				Path:        "dir1/empty.txt",
				Permissions: 0600,
				UID:         1001,
				GID:         1001,
			},
		},
	}
	err := mutatePaths(mfs, opts, ic)
	require.NoError(t, err)

	// Verify that the directory was created.
	dirInfo, err := mfs.Stat("dir1")
	require.NoError(t, err)
	require.True(t, dirInfo.IsDir())
	// Expected permission is now 0777 because the symlink mutation follows the link
	// and resets the directory's permission.
	require.Equal(t, fs.FileMode(0777), dirInfo.Mode().Perm())

	// Verify that the empty file exists and has the correct final permissions.
	fileInfo, err := mfs.Stat("dir1/empty.txt")
	require.NoError(t, err)
	require.False(t, fileInfo.IsDir())
	require.Equal(t, fs.FileMode(0600), fileInfo.Mode().Perm())

	// Verify that the hardlink exists.
	data, err := mfs.ReadFile("hardlink.txt")
	require.NoError(t, err)
	// Since the empty file is empty, the data should be empty.
	require.Empty(t, data)

	// Verify that the symlink still points to the correct target.
	linkTarget, err := mfs.Readlink("symlink.txt")
	require.NoError(t, err)
	require.Equal(t, "dir1", linkTarget)
}
