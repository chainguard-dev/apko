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
)

func ResolvePath(p string, includePaths []string) (string, error) {
	_, err := os.Stat(p)
	if err == nil {
		return p, nil
	}
	for _, pathPrefix := range includePaths {
		resolvedPath := path.Join(pathPrefix, p)
		_, err := os.Stat(resolvedPath)
		if err == nil {
			return resolvedPath, nil
		}
	}
	return "", os.ErrNotExist
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
