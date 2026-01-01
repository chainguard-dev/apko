// Copyright 2024 Chainguard, Inc.
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

package apkcompat

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"

	"github.com/spf13/cobra"

	"chainguard.dev/apko/pkg/apk/apk"
	apkfs "chainguard.dev/apko/pkg/apk/fs"
)

func updateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update repository indexes",
		Long: `apko-as-apk update forces updating of the indexes from all configured package
repositories. This command is not needed in normal operation as all applets
requiring indexes will automatically refresh them after caching time expires.`,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUpdate(cmd.Context())
		},
	}

	return cmd
}

func runUpdate(ctx context.Context) error {
	slog.Info("apko-as-apk update", "root", globalOpts.Root)

	// Determine architecture
	arch := globalOpts.Arch
	if arch == "" {
		arch = runtime.GOARCH
	}

	// Setup filesystem
	fs := apkfs.DirFS(ctx, globalOpts.Root)

	// Determine cache directory
	cacheDir := globalOpts.CacheDir
	if cacheDir == "" {
		cacheDir = "/var/cache/apk"
	}

	// Create APK instance
	apkOpts := []apk.Option{
		apk.WithFS(fs),
		apk.WithArch(arch),
	}

	// For update, we always want to use the cache
	cache := apk.NewCache(false) // false = don't use offline cache
	apkOpts = append(apkOpts, apk.WithCache(cacheDir, false, cache))

	if globalOpts.AllowUntrusted {
		apkOpts = append(apkOpts, apk.WithIgnoreIndexSignatures(true))
	}

	apkClient, err := apk.New(ctx, apkOpts...)
	if err != nil {
		return fmt.Errorf("failed to create APK client: %w", err)
	}

	// Get repositories
	repos, err := apkClient.GetRepositories()
	if err != nil {
		return fmt.Errorf("failed to get repositories: %w", err)
	}

	if len(repos) == 0 {
		return fmt.Errorf("no repositories configured")
	}

	// Force fetch of repository indexes (ignoring signatures if requested)
	slog.Info("Fetching repository indexes", "count", len(repos))
	indexes, err := apkClient.GetRepositoryIndexes(ctx, globalOpts.AllowUntrusted)
	if err != nil {
		return fmt.Errorf("failed to fetch repository indexes: %w", err)
	}

	// Display information about repositories and packages
	if !globalOpts.Quiet {
		unavailable := 0
		stale := 0

		// Print repository information if verbose
		if globalOpts.Verbose > 0 {
			for i, repo := range repos {
				if i < len(indexes) && indexes[i] != nil {
					idx := indexes[i]
					fmt.Fprintf(os.Stderr, "%s [%s]\n", idx.Name(), repo)
				}
			}
		}

		// Count distinct packages (by name)
		distinctPackages := make(map[string]bool)
		for _, idx := range indexes {
			if idx == nil {
				unavailable++
				continue
			}
			for _, pkg := range idx.Packages() {
				distinctPackages[pkg.Name] = true
			}
		}

		// Print summary
		statusMsg := "OK:"
		if unavailable > 0 || stale > 0 {
			statusMsg = fmt.Sprintf("%d unavailable, %d stale;", unavailable, stale)
		}

		fmt.Fprintf(os.Stderr, "%s %d distinct packages available\n", statusMsg, len(distinctPackages))

		if unavailable > 0 || stale > 0 {
			return fmt.Errorf("some repositories unavailable or stale")
		}
	}

	return nil
}
