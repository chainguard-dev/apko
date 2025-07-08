// Copyright 2022, 2023 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fs

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEmptyDir(t *testing.T) {
	dir := t.TempDir()
	fs := DirFS(t.Context(), dir)
	require.NotNil(t, fs, "fs should be created")
}

func TestExistingDir(t *testing.T) {
	var (
		err     error
		content []byte
	)
	files := []struct {
		path    string
		dir     bool
		perms   os.FileMode
		content []byte
	}{
		{"a/b", true, 0o755, nil},
		{"a/b/c", false, 0o644, []byte("hello")},
		{"foo/bar", true, 0o700, nil},
		{"foo/bar/world", false, 0o600, []byte("world")},
	}

	dir := t.TempDir()
	for _, f := range files {
		if f.dir {
			err = os.MkdirAll(filepath.Join(dir, f.path), f.perms)
			require.NoError(t, err, "error creating dir %s", f.path)
		} else {
			err = os.WriteFile(filepath.Join(dir, f.path), f.content, f.perms)
			require.NoError(t, err, "error creating file %s", f.path)
		}
	}

	fs := DirFS(t.Context(), dir)
	require.NotNil(t, fs, "fs should be created")

	for _, f := range files {
		if f.dir {
			continue
		}
		content, err = fs.ReadFile(f.path)
		require.NoError(t, err, "error reading file %s", f.path)
		require.Equal(t, f.content, content, "content of %s should be %s", f.path, f.content)
	}
}

func TestMissingDir(t *testing.T) {
	dir := t.TempDir()
	fs := DirFS(t.Context(), dir)
	require.NotNil(t, fs, "fs should be created")
	err := fs.WriteFile("foo/bar/world", []byte("world"), 0o600)
	require.Error(t, err, "expected error writing file foo/bar/world when foo/bar dir does not exist")
}

func TestCaseInsensitive(t *testing.T) {
	var (
		err error
	)
	files := []struct {
		path    string
		dir     bool
		perms   os.FileMode
		content []byte
		onDisk  bool // whether it should be on the local filesystem
	}{
		{"a/b", true, 0o755, nil, true},
		{"a/b/c", false, 0o644, []byte("hello lower lower"), true},
		{"a/b/C", false, 0o644, []byte("hello lower upper"), false},
		{"a/B", true, 0o755, nil, false},
		{"a/B/c", false, 0o644, []byte("hello upper lower"), false},
	}

	dir := t.TempDir()
	// force underlying filesystem to be treated as case insensitive
	fs := DirFS(t.Context(), dir, DirFSWithCaseSensitive(false))
	require.NotNil(t, fs, "fs should be created")

	// create the files in the fs
	for _, f := range files {
		if f.dir {
			err = fs.MkdirAll(f.path, f.perms)
			require.NoError(t, err, "error creating dir %s", f.path)
		} else {
			err = fs.WriteFile(f.path, f.content, f.perms)
			require.NoError(t, err, "error creating file %s", f.path)
		}
	}

	// check the files in the fs
	for _, f := range files {
		if f.dir {
			continue
		}
		content, err := fs.ReadFile(f.path)
		require.NoError(t, err, "error reading file %s", f.path)
		require.Equal(t, string(f.content), string(content), "content of %s should be %s", f.path, f.content)
	}

	// check the files in the filesystem
	for _, f := range files {
		if !f.onDisk {
			continue
		}
		if f.dir {
			fi, err := os.Stat(filepath.Join(dir, f.path))
			require.NoError(t, err, "error stating file %s", f.path)
			require.True(t, fi.IsDir(), "file %s should be a dir", f.path)
		} else {
			content, err := os.ReadFile(filepath.Join(dir, f.path))
			require.NoError(t, err, "error reading file %s", f.path)
			require.Equal(t, string(f.content), string(content), "content of %s should be %s", f.path, f.content)
		}
	}
}

func TestDirFSConsistentOrdering(t *testing.T) {
	dir := t.TempDir()
	// force underlying filesystem to be treated as case insensitive
	fsys := DirFS(t.Context(), dir)
	entries := []testDirEntry{
		{"dir1", 0o777, true, nil},
		{"dir1/subdir1", 0o777, true, nil},
		{"dir1/subdir1/file1", 0o644, false, nil},
		{"dir1/subdir1/file2", 0o644, false, nil},
		{"dir1/subdir2", 0o777, true, nil},
		{"dir1/subdir2/file1", 0o644, false, nil},
		{"dir1/subdir2/file2", 0o644, false, nil},
		{"dir1/subdir3", 0o777, true, nil},
		{"dir1/subdir3/file1", 0o644, false, nil},
		{"dir1/subdir3/file2", 0o644, false, nil},
		{"dir2", 0o777, true, nil},
		{"dir2/subdir1", 0o777, true, nil},
		{"dir2/subdir1/file1", 0o644, false, nil},
		{"dir2/subdir1/file2", 0o644, false, nil},
		{"dir2/subdir2", 0o777, true, nil},
		{"dir2/subdir2/file1", 0o644, false, nil},
		{"dir2/subdir2/file2", 0o644, false, nil},
		{"dir2/subdir3", 0o777, true, nil},
		{"dir2/subdir3/file1", 0o644, false, nil},
		{"dir2/subdir3/file2", 0o644, false, nil},
		{"dir2/file1", 0o644, false, nil},
		{"dir2/file2", 0o644, false, nil},
		{"dir2/file3", 0o644, false, nil},
	}
	for _, e := range entries {
		var err error
		if e.dir {
			err = fsys.Mkdir(e.path, e.perms)
		} else {
			err = fsys.WriteFile(e.path, e.content, e.perms)
		}
		require.NoError(t, err)
	}
	// now walk the tree, we should get consistent results each time
	var results []string
	for i := 0; i < 10; i++ {
		var result []string
		err := fs.WalkDir(fsys, "/", func(path string, _ fs.DirEntry, err error) error {
			require.NoError(t, err)
			result = append(result, path)
			return nil
		})
		require.NoError(t, err)
		if i == 0 {
			results = result
			continue
		}
		require.Equal(t, results, result, "iteration %d", i)
	}
	// all results should be the same
}
