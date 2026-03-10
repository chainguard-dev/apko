// Copyright 2025 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package paths

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

func ResolvePath(p string, includePaths []string) (string, error) {
	// First, check if p contains any path traversal attempts
	if containsPathTraversal(p) {
		return "", fmt.Errorf("path contains traversal sequence: %s", p)
	}

	_, err := os.Stat(p)
	if err == nil {
		// Validate that the absolute path doesn't escape current directory
		absPath, err := filepath.Abs(p)
		if err != nil {
			return "", fmt.Errorf("failed to resolve absolute path: %w", err)
		}
		return absPath, nil
	}

	for _, pathPrefix := range includePaths {
		resolvedPath := filepath.Join(pathPrefix, p)

		// Validate that resolved path is within the pathPrefix
		cleanPrefix := filepath.Clean(pathPrefix)
		cleanResolved := filepath.Clean(resolvedPath)

		rel, err := filepath.Rel(cleanPrefix, cleanResolved)
		if err != nil || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." {
			// Skip this path as it attempts to escape the include directory
			continue
		}

		_, err = os.Stat(resolvedPath)
		if err == nil {
			return resolvedPath, nil
		}
	}
	return "", os.ErrNotExist
}

// containsPathTraversal checks if a path contains obvious traversal sequences
func containsPathTraversal(p string) bool {
	// Check for explicit .. sequences
	if strings.Contains(p, "..") {
		return true
	}
	// Check for encoded path traversal attempts
	if strings.Contains(p, "%2e%2e") || strings.Contains(p, "%2E%2E") {
		return true
	}
	return false
}

// AdvertisedCachedFile will create a symlink at `dst` pointing to `src`.
//
// In the case that `dst` already exists, another process had already created the symlink
// and we can safely move on. We will also perform a best-effort attempt to clean up the
// unadvertised file at `src`.
func AdvertiseCachedFile(src, dst string) error {
	// Prefer relative symlinks
	rel, err := filepath.Rel(filepath.Dir(dst), src)
	if err != nil {
		rel = src
	}

	// Check what exists at dst using Lstat (doesn't follow symlinks).
	// This lets us distinguish between "nothing exists" and "broken symlink".
	if _, err := os.Lstat(dst); err == nil {
		// Something exists at dst. Check if it's a valid symlink by following it.
		if _, err := os.Stat(dst); err == nil {
			// Valid symlink exists - another process already advertised.
			// Clean up src since it's unadvertised and return.
			_ = os.Remove(src)
			return nil
		}
		// Broken symlink (Lstat succeeded but Stat failed) - remove it.
		if err := os.Remove(dst); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				// Race condition: something removed it between our Lstat and Remove.
				// Re-run to handle it properly.
				return AdvertiseCachedFile(src, dst)
			}
			return fmt.Errorf("removing broken symlink %s: %w", dst, err)
		}
	}

	// Create the symlink.
	if err := os.Symlink(rel, dst); err != nil {
		if errors.Is(err, os.ErrExist) {
			// Race condition: something appeared between our Lstat check and Symlink.
			// Re-run to handle it properly.
			return AdvertiseCachedFile(src, dst)
		}
		return fmt.Errorf("linking (cached) %s to %s: %w", rel, dst, err)
	}
	return nil
}
