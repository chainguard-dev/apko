// Copyright 2025 Chainguard, Inc.
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

package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCleanImpl(t *testing.T) {
	ctx := context.Background()

	t.Run("clean existing cache", func(t *testing.T) {
		// Create a temporary cache directory
		tmpDir := t.TempDir()
		cacheDir := filepath.Join(tmpDir, "cache")
		err := os.MkdirAll(cacheDir, 0755)
		require.NoError(t, err)

		// Create some dummy cache files
		testFiles := []string{
			"https%3A%2F%2Fdl-cdn.alpinelinux.org%2Falpine%2Fv3.18/x86_64/APKINDEX.tar.gz",
			"https%3A%2F%2Fdl-cdn.alpinelinux.org%2Falpine%2Fv3.18/x86_64/package1.apk",
			"https%3A%2F%2Fdl-cdn.alpinelinux.org%2Falpine%2Fv3.18/x86_64/package2.apk",
		}

		for _, file := range testFiles {
			dir := filepath.Dir(filepath.Join(cacheDir, file))
			err := os.MkdirAll(dir, 0755)
			require.NoError(t, err)
			
			err = os.WriteFile(filepath.Join(cacheDir, file), []byte("dummy content"), 0644)
			require.NoError(t, err)
		}

		// Verify cache exists
		_, err = os.Stat(cacheDir)
		require.NoError(t, err)

		// Clean the cache
		err = CleanImpl(ctx, cacheDir, false)
		require.NoError(t, err)

		// Verify cache is gone
		_, err = os.Stat(cacheDir)
		require.True(t, os.IsNotExist(err))
	})

	t.Run("dry run does not delete cache", func(t *testing.T) {
		// Create a temporary cache directory
		tmpDir := t.TempDir()
		cacheDir := filepath.Join(tmpDir, "cache")
		err := os.MkdirAll(cacheDir, 0755)
		require.NoError(t, err)

		// Create a dummy cache file
		testFile := filepath.Join(cacheDir, "test.apk")
		err = os.WriteFile(testFile, []byte("dummy content"), 0644)
		require.NoError(t, err)

		// Run clean with dry-run
		err = CleanImpl(ctx, cacheDir, true)
		require.NoError(t, err)

		// Verify cache still exists
		_, err = os.Stat(cacheDir)
		require.NoError(t, err)
		_, err = os.Stat(testFile)
		require.NoError(t, err)
	})

	t.Run("non-existent cache directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		cacheDir := filepath.Join(tmpDir, "non-existent")

		// Clean should not error on non-existent directory
		err := CleanImpl(ctx, cacheDir, false)
		require.NoError(t, err)
	})

	t.Run("cache path is file not directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		cacheFile := filepath.Join(tmpDir, "file")
		err := os.WriteFile(cacheFile, []byte("not a directory"), 0644)
		require.NoError(t, err)

		// Should error when cache path is a file
		err = CleanImpl(ctx, cacheFile, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not a directory")
	})
}

func TestCalculateDirSize(t *testing.T) {
	tmpDir := t.TempDir()

	// Create files with known sizes
	files := map[string]int{
		"file1.txt": 100,
		"file2.txt": 200,
		"subdir/file3.txt": 300,
	}

	totalSize := int64(0)
	for path, size := range files {
		fullPath := filepath.Join(tmpDir, path)
		dir := filepath.Dir(fullPath)
		err := os.MkdirAll(dir, 0755)
		require.NoError(t, err)

		content := make([]byte, size)
		err = os.WriteFile(fullPath, content, 0644)
		require.NoError(t, err)
		totalSize += int64(size)
	}

	// Calculate directory size
	size, err := calculateDirSize(tmpDir)
	require.NoError(t, err)
	require.Equal(t, totalSize, size)
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes    int64
		expected string
	}{
		{0, "0 B"},
		{100, "100 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
		{1099511627776, "1.0 TB"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatBytes(tt.bytes)
			require.Equal(t, tt.expected, result)
		})
	}
}