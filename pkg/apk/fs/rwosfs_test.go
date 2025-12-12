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
		// ReadFile() fails on the following and doesn't fall back to
		// trying to adjust the permissions.
		// {"foo/bar/shadow", false, 0o000, []byte("shadow")},
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

// DirFS has differing behaviors depending on handling an inaccessible
// file due to permissions in ReadFile(), OpenFile(), and Open().
func TestExistingDirUsingOpen(t *testing.T) {
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
		{"foo/bar/shadow", false, 0o000, []byte("shadow")},
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
		fd, err := fs.Open(f.path)
		require.NoError(t, err, "error opening file %s", f.path)

		content = make([]byte, len(f.content))
		_, err = fd.Read(content)
		require.NoError(t, err, "error reading file %s", f.path)

		require.Equal(t, f.content, content, "content of %s should be %s", f.path, f.content)

		fd.Close()
		// Ensure 0 permissions on the original file were maintained/reset correctly
		if f.perms == 0o000 {
			_, err = os.ReadFile(f.path)
			require.Error(t, err, "expected permissions error reading %s", f.path)
		}
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
	for i := range 10 {
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

// TestWriteReadCaching tests that WriteFile followed by ReadFile returns the correct data.
// This test demonstrates a bug where dirFS caches an empty buffer after WriteFile,
// causing subsequent ReadFile operations to return zeros instead of the actual file content.
func TestWriteReadCaching(t *testing.T) {
	dir := t.TempDir()
	fsys := DirFS(t.Context(), dir)
	require.NotNil(t, fsys, "fs should be created")

	// Test data
	testData := []byte("Hello, World! This is test data.")
	testPath := "test-file.txt"

	// Write the file through dirFS
	err := fsys.WriteFile(testPath, testData, 0o644)
	require.NoError(t, err, "WriteFile should succeed")

	// Verify the file was written to disk correctly
	diskData, err := os.ReadFile(filepath.Join(dir, testPath))
	require.NoError(t, err, "should be able to read from disk")
	require.Equal(t, testData, diskData, "disk file should contain correct data")

	// Read the file back through dirFS - this should return the same data
	readData, err := fsys.ReadFile(testPath)
	require.NoError(t, err, "ReadFile should succeed")
	require.Equal(t, testData, readData, "ReadFile should return the same data that was written")
}

// TestWriteReadCachingMultiple tests multiple write-read cycles to ensure caching works correctly.
func TestWriteReadCachingMultiple(t *testing.T) {
	dir := t.TempDir()
	fsys := DirFS(t.Context(), dir)
	require.NotNil(t, fsys, "fs should be created")

	testPath := "multi-test.txt"

	// Multiple write-read cycles with different data
	testCases := []struct {
		name string
		data []byte
	}{
		{"first write", []byte("First write data")},
		{"second write", []byte("Second write with different data")},
		{"third write", []byte("Third write with even more different data!")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Write through dirFS
			err := fsys.WriteFile(testPath, tc.data, 0o644)
			require.NoError(t, err, "WriteFile should succeed")

			// Read back through dirFS
			readData, err := fsys.ReadFile(testPath)
			require.NoError(t, err, "ReadFile should succeed")
			require.Equal(t, tc.data, readData, "ReadFile should return the data that was just written")

			// Verify disk has correct data
			diskData, err := os.ReadFile(filepath.Join(dir, testPath))
			require.NoError(t, err, "should be able to read from disk")
			require.Equal(t, tc.data, diskData, "disk file should contain correct data")
		})
	}
}

// TestWriteReadAfterStat tests that Stat doesn't interfere with read caching.
// This is important because Stat updates internal dirFS state that affects
// whether ReadFile uses disk or cached overlay.
func TestWriteReadAfterStat(t *testing.T) {
	dir := t.TempDir()
	fsys := DirFS(t.Context(), dir)
	require.NotNil(t, fsys, "fs should be created")

	testData := []byte("Test data after stat")
	testPath := "stat-test.txt"

	// Write the file
	err := fsys.WriteFile(testPath, testData, 0o644)
	require.NoError(t, err, "WriteFile should succeed")

	// Call Stat on the file (this updates dirFS internal state)
	fi, err := fsys.Stat(testPath)
	require.NoError(t, err, "Stat should succeed")
	require.Equal(t, int64(len(testData)), fi.Size(), "Stat should report correct size")

	// Now read the file - this should still return correct data
	readData, err := fsys.ReadFile(testPath)
	require.NoError(t, err, "ReadFile should succeed after Stat")
	require.Equal(t, testData, readData, "ReadFile should return correct data even after Stat")
}

// TestOpenFileWriteReadCaching tests the OpenFile/Write/Close pattern followed by ReadFile.
// This mimics the pattern used in updateScriptsTar where files are created with OpenFile,
// written to, closed, and then read back later.
func TestOpenFileWriteReadCaching(t *testing.T) {
	dir := t.TempDir()
	fsys := DirFS(t.Context(), dir)
	require.NotNil(t, fsys, "fs should be created")

	testData := []byte("Data written via OpenFile/Write/Close")

	// Create directory first
	err := fsys.MkdirAll("subdir", 0o755)
	require.NoError(t, err, "MkdirAll should succeed")

	testPath := "subdir/openfile-test.txt"

	// Write using OpenFile/Write/Close pattern
	f, err := fsys.OpenFile(testPath, os.O_CREATE|os.O_WRONLY, 0o644)
	require.NoError(t, err, "OpenFile should succeed")

	n, err := f.Write(testData)
	require.NoError(t, err, "Write should succeed")
	require.Equal(t, len(testData), n, "should write all bytes")

	err = f.Close()
	require.NoError(t, err, "Close should succeed")

	// Verify disk has correct data
	diskData, err := os.ReadFile(filepath.Join(dir, testPath))
	require.NoError(t, err, "should be able to read from disk")
	require.Equal(t, testData, diskData, "disk file should contain correct data")

	// Now read through dirFS - this should return correct data
	readData, err := fsys.ReadFile(testPath)
	require.NoError(t, err, "ReadFile should succeed")
	require.Equal(t, testData, readData, "ReadFile should return correct data after OpenFile/Write/Close")
}

// TestScriptsTarPattern tests the exact pattern used by updateScriptsTar:
// 1. Stat the file
// 2. ReadFile to get existing content
// 3. OpenFile to create temp file
// 4. Write existing + new content
// 5. Close temp file
// 6. WriteFile to move temp to final
// 7. ReadFile the final file
func TestScriptsTarPattern(t *testing.T) {
	dir := t.TempDir()
	fsys := DirFS(t.Context(), dir)
	require.NotNil(t, fsys, "fs should be created")

	// Create directory
	err := fsys.MkdirAll("lib/apk/db", 0o755)
	require.NoError(t, err, "MkdirAll should succeed")

	scriptsPath := "lib/apk/db/scripts.tar"
	tempPath := scriptsPath + ".tmp"

	// Initial content (simulating existing scripts)
	initialData := []byte("existing tar content")

	// Step 1: Create initial file
	err = fsys.WriteFile(scriptsPath, initialData, 0o644)
	require.NoError(t, err, "initial WriteFile should succeed")

	// Step 2: Stat the file (like updateScriptsTar does)
	fi, err := fsys.Stat(scriptsPath)
	require.NoError(t, err, "Stat should succeed")
	require.Equal(t, int64(len(initialData)), fi.Size(), "Stat should report correct size")

	// Step 3: ReadFile to get existing content (like updateScriptsTar does)
	existingData, err := fsys.ReadFile(scriptsPath)
	require.NoError(t, err, "ReadFile should succeed")
	require.Equal(t, initialData, existingData, "ReadFile should return initial data")

	// Step 4: Create temp file with OpenFile
	tempFile, err := fsys.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	require.NoError(t, err, "OpenFile for temp should succeed")

	// Step 5: Write existing + new content to temp
	combinedData := make([]byte, len(existingData))
	copy(existingData, combinedData)
	combinedData = append(combinedData, []byte(" + new content")...)

	_, err = tempFile.Write(combinedData)
	require.NoError(t, err, "Write to temp should succeed")

	err = tempFile.Close()
	require.NoError(t, err, "Close temp should succeed")

	// Step 6: Read temp file data
	tempData, err := fsys.ReadFile(tempPath)
	require.NoError(t, err, "ReadFile temp should succeed")
	require.Equal(t, combinedData, tempData, "temp file should have combined data")

	// Step 7: WriteFile to move temp to final
	err = fsys.WriteFile(scriptsPath, tempData, 0o644)
	require.NoError(t, err, "WriteFile to final location should succeed")

	// Step 8: Verify final file on disk
	diskData, err := os.ReadFile(filepath.Join(dir, scriptsPath))
	require.NoError(t, err, "should be able to read final file from disk")
	require.Equal(t, combinedData, diskData, "disk file should have combined data")

	// Step 9: ReadFile the final file through dirFS - THIS IS WHERE THE BUG MANIFESTS
	finalData, err := fsys.ReadFile(scriptsPath)
	require.NoError(t, err, "ReadFile final should succeed")
	require.Equal(t, combinedData, finalData, "ReadFile should return combined data, not zeros")
}
