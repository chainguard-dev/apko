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
	"fmt"
	"os"
	"path/filepath"

	"github.com/chainguard-dev/clog"
	"github.com/spf13/cobra"
)

func cleanCmd() *cobra.Command {
	var cacheDir string
	var dryRun bool

	cmd := &cobra.Command{
		Use:   "clean",
		Short: "Clean the apko cache directory",
		Long: `Clean the apko cache directory by removing all cached APK packages and APKINDEX files.

If no cache directory is specified, the default cache directory is used:
  - On Linux: ~/.cache/dev.chainguard.go-apk
  - On macOS: ~/Library/Caches/dev.chainguard.go-apk
  - On Windows: %LocalAppData%\dev.chainguard.go-apk`,
		Example: `  apko clean
  apko clean --cache-dir /custom/cache/path
  apko clean --dry-run`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return CleanImpl(cmd.Context(), cacheDir, dryRun)
		},
	}

	cmd.Flags().StringVar(&cacheDir, "cache-dir", "", "directory containing the apk cache (defaults to system cache directory)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show cache size without deleting")

	return cmd
}

func CleanImpl(ctx context.Context, cacheDir string, dryRun bool) error {
	log := clog.FromContext(ctx)

	// Determine cache directory
	if cacheDir == "" {
		var err error
		cacheDir, err = os.UserCacheDir()
		if err != nil {
			return fmt.Errorf("failed to determine user cache directory: %w", err)
		}
		cacheDir = filepath.Join(cacheDir, "dev.chainguard.go-apk")
	} else {
		var err error
		cacheDir, err = filepath.Abs(cacheDir)
		if err != nil {
			return fmt.Errorf("failed to resolve cache directory path: %w", err)
		}
	}

	log.Infof("Cleaning cache directory: %s", cacheDir)

	// Check if the cache directory exists
	info, err := os.Stat(cacheDir)
	if err != nil {
		if os.IsNotExist(err) {
			log.Infof("Cache directory does not exist, nothing to clean")
			return nil
		}
		return fmt.Errorf("failed to stat cache directory: %w", err)
	}

	if !info.IsDir() {
		return fmt.Errorf("cache path is not a directory: %s", cacheDir)
	}

	// Calculate cache size
	size, err := calculateDirSize(cacheDir)
	if err != nil {
		return fmt.Errorf("failed to calculate cache size: %w", err)
	}

	log.Infof("Cache size: %s", formatBytes(size))

	if dryRun {
		log.Infof("Dry run mode: cache directory will not be deleted")
		return nil
	}

	// Remove the cache directory and all its contents
	if err := os.RemoveAll(cacheDir); err != nil {
		return fmt.Errorf("failed to remove cache directory: %w", err)
	}

	log.Infof("Cache directory cleaned successfully")
	return nil
}

// calculateDirSize recursively calculates the total size of a directory
func calculateDirSize(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size, err
}

// formatBytes formats bytes into human-readable format
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
