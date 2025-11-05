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
	"strings"
	"time"

	"github.com/spf13/cobra"

	"chainguard.dev/apko/pkg/apk/apk"
	apkfs "chainguard.dev/apko/pkg/apk/fs"
)

type addOptions struct {
	initdb         bool
	latest         bool
	upgrade        bool
	virtual        string
	noChown        bool
	simulate       bool
	noScripts      bool
	cleanProtected bool
}

func addCmd() *cobra.Command {
	opts := &addOptions{}

	cmd := &cobra.Command{
		Use:   "add [OPTIONS] CONSTRAINTS...",
		Short: "Add or modify constraints in WORLD and commit changes",
		Long: `apko-as-apk add adds or updates given constraints to WORLD and commit
changes to disk. This usually involves installing new packages.`,
		SilenceErrors: true,
		Args:          cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAdd(cmd.Context(), opts, args)
		},
	}

	// Add-specific options
	cmd.Flags().BoolVar(&opts.initdb, "initdb", false, "Initialize a new package database")
	cmd.Flags().BoolVarP(&opts.latest, "latest", "l", false, "Always choose the latest package by version")
	cmd.Flags().BoolVarP(&opts.upgrade, "upgrade", "u", false, "Upgrade PACKAGES and its dependencies")
	cmd.Flags().StringVarP(&opts.virtual, "virtual", "t", "", "Create virtual package NAME with given dependencies")
	cmd.Flags().BoolVar(&opts.noChown, "no-chown", false, "Do not change file owner or group")
	cmd.Flags().BoolVarP(&opts.simulate, "simulate", "s", false, "Simulate the requested operation without making any changes")
	cmd.Flags().BoolVar(&opts.noScripts, "no-scripts", false, "Do not execute any scripts")
	cmd.Flags().BoolVar(&opts.cleanProtected, "clean-protected", false, "Do not create .apk-new files in configuration directories")

	return cmd
}

func runAdd(ctx context.Context, opts *addOptions, packages []string) error {
	slog.Info("apko-as-apk add", "root", globalOpts.Root, "packages", packages)

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

	if !globalOpts.NoCache {
		cache := apk.NewCache(!globalOpts.ForceRefresh)
		apkOpts = append(apkOpts, apk.WithCache(cacheDir, false, cache))
	}

	if globalOpts.AllowUntrusted {
		apkOpts = append(apkOpts, apk.WithIgnoreIndexSignatures(true))
	}

	if opts.noChown {
		apkOpts = append(apkOpts, apk.WithIgnoreMknodErrors(true))
	}

	apkClient, err := apk.New(ctx, apkOpts...)
	if err != nil {
		return fmt.Errorf("failed to create APK client: %w", err)
	}

	// Initialize database if requested
	if opts.initdb {
		slog.Info("Initializing APK database")

		// Get repository list
		repos, err := getRepositories(ctx, apkClient)
		if err != nil {
			return fmt.Errorf("failed to get repositories: %w", err)
		}

		if err := apkClient.InitDB(ctx, repos...); err != nil {
			return fmt.Errorf("failed to initialize database: %w", err)
		}

		// Install keys if keys directory specified or use default
		keysDir := globalOpts.KeysDir
		if keysDir == "" {
			keysDir = "/etc/apk/keys"
		}

		if err := installKeys(ctx, apkClient, keysDir); err != nil {
			return fmt.Errorf("failed to install keys: %w", err)
		}
	}

	// Get current repositories
	repos, err := apkClient.GetRepositories()
	if err != nil {
		return fmt.Errorf("failed to get repositories: %w", err)
	}

	// Add any additional repositories from command line
	if len(globalOpts.Repository) > 0 {
		repos = append(repos, globalOpts.Repository...)
		if err := apkClient.SetRepositories(ctx, repos); err != nil {
			return fmt.Errorf("failed to set repositories: %w", err)
		}
	}

	// Get current world
	world, err := apkClient.GetWorld()
	if err != nil {
		return fmt.Errorf("failed to get world: %w", err)
	}

	// Handle virtual package
	if opts.virtual != "" {
		return fmt.Errorf("virtual packages not yet implemented")
	}

	// Add packages to world
	for _, pkg := range packages {
		// Check if it's a local .apk file
		if strings.HasSuffix(pkg, ".apk") {
			return fmt.Errorf("local .apk files not yet fully supported: %s", pkg)
		}

		// Add to world
		world = append(world, pkg)
	}

	slog.Info("Setting world", "packages", world)
	if err := apkClient.SetWorld(ctx, world); err != nil {
		return fmt.Errorf("failed to set world: %w", err)
	}

	if opts.simulate {
		slog.Info("Simulation mode - would resolve and install packages")
		// TODO: show what would be installed
		return nil
	}

	// Resolve dependencies
	slog.Info("Resolving world")
	if _, _, err := apkClient.ResolveWorld(ctx); err != nil {
		return fmt.Errorf("failed to resolve world: %w", err)
	}

	// Install packages
	slog.Info("Installing packages")
	var sourceDateEpoch *time.Time
	diffs, err := apkClient.FixateWorld(ctx, sourceDateEpoch)
	if err != nil {
		return fmt.Errorf("failed to install packages: %w", err)
	}

	// Report changes
	if !globalOpts.Quiet {
		for _, diff := range diffs {
			pkg := diff.Package
			fmt.Fprintf(os.Stderr, "(%d/%d) Installing %s (%s)\n",
				pkg.InstalledSize, pkg.Size,
				pkg.Name, pkg.Version)
		}
		fmt.Fprintf(os.Stderr, "OK: %d packages installed\n", len(diffs))
	}

	return nil
}

func getRepositories(ctx context.Context, apkClient *apk.APK) ([]string, error) {
	// Try to read from repositories file if specified
	if globalOpts.RepositoriesFile != "" {
		data, err := os.ReadFile(globalOpts.RepositoriesFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read repositories file: %w", err)
		}
		lines := strings.Split(string(data), "\n")
		var repos []string
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				repos = append(repos, line)
			}
		}
		return repos, nil
	}

	// Try to get from existing system
	repos, err := apkClient.GetRepositories()
	if err == nil && len(repos) > 0 {
		return repos, nil
	}

	// Add command-line repositories
	if len(globalOpts.Repository) > 0 {
		return globalOpts.Repository, nil
	}

	// Default repositories (Alpine 3.22 as example)
	return []string{
		"https://dl-cdn.alpinelinux.org/alpine/edge/main",
		"https://dl-cdn.alpinelinux.org/alpine/edge/community",
	}, nil
}

func installKeys(ctx context.Context, apkClient *apk.APK, keysDir string) error {
	// Check if keys directory exists
	if _, err := os.Stat(keysDir); os.IsNotExist(err) {
		slog.Warn("Keys directory does not exist, skipping key installation", "dir", keysDir)
		return nil
	}

	entries, err := os.ReadDir(keysDir)
	if err != nil {
		return fmt.Errorf("failed to read keys directory: %w", err)
	}

	var keyFiles []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".pub") {
			keyFiles = append(keyFiles, fmt.Sprintf("%s/%s", keysDir, entry.Name()))
		}
	}

	if len(keyFiles) == 0 {
		slog.Warn("No keys found in directory", "dir", keysDir)
		return nil
	}

	slog.Info("Installing keys", "count", len(keyFiles))
	return apkClient.InitKeyring(ctx, keyFiles, nil)
}
