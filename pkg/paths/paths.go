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
	// Check if the destination already exists.
	if _, err := os.Stat(dst); err == nil {
		// Since `src` is unadvertised, it is safe to remove it. Ideally we want this to succeeds,
		// but we don't want to fail a build just because we couldn't clean up. This will be
		// left for background clean up process based on age.
		_ = os.Remove(src)
		return nil
	}
	// Create the symlink.
	if err := os.Symlink(rel, dst); err != nil {
		// Ignore already exists errors. We don't even want to do clean up here even when
		// the symlink is pointing somewhere elese, to avoid relying too much on file system
		// remantics/eventual consistency, etc.
		if errors.Is(err, os.ErrExist) {
			return nil
		}
		return fmt.Errorf("linking (cached) %s to %s: %w", rel, dst, err)
	}
	return nil
}
