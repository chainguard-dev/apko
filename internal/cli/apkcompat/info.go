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
	"os"
	"runtime"

	"github.com/spf13/cobra"

	"chainguard.dev/apko/pkg/apk/apk"
	apkfs "chainguard.dev/apko/pkg/apk/fs"
)

type infoOptions struct {
	all         bool
	description bool
	installed   bool
	contents    bool
	provides    bool
	rdepends    bool
	depends     bool
	size        bool
	webpage     bool
	whoOwns     bool
	installIf   bool
	license     bool
	replaces    bool
	rinstallIf  bool
	triggers    bool
}

func infoCmd() *cobra.Command {
	opts := &infoOptions{}

	cmd := &cobra.Command{
		Use:   "info [OPTIONS] PACKAGES...",
		Short: "Give detailed information about packages",
		Long: `apko-as-apk info prints information known about the listed packages. By default, it
prints the description, webpage, and installed size of the package.`,
		SilenceErrors: true,
		Args:          cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInfo(cmd.Context(), opts, args)
		},
	}

	// Info-specific options
	cmd.Flags().BoolVarP(&opts.all, "all", "a", false, "List all information known about the package")
	cmd.Flags().BoolVarP(&opts.description, "description", "d", false, "Print the package description")
	cmd.Flags().BoolVarP(&opts.installed, "installed", "e", false, "Check package installed status")
	cmd.Flags().BoolVarP(&opts.contents, "contents", "L", false, "List files included in the package")
	cmd.Flags().BoolVarP(&opts.provides, "provides", "P", false, "List what the package provides")
	cmd.Flags().BoolVarP(&opts.rdepends, "rdepends", "r", false, "List reverse dependencies of the package")
	cmd.Flags().BoolVarP(&opts.depends, "depends", "R", false, "List the dependencies of the package")
	cmd.Flags().BoolVarP(&opts.size, "size", "s", false, "Print the package's installed size")
	cmd.Flags().BoolVarP(&opts.webpage, "webpage", "w", false, "Print the URL for the package's upstream webpage")
	cmd.Flags().BoolVarP(&opts.whoOwns, "who-owns", "W", false, "Print the package which owns the specified file")
	cmd.Flags().BoolVar(&opts.installIf, "install-if", false, "List the package's install_if rule")
	cmd.Flags().BoolVar(&opts.license, "license", false, "Print the package SPDX license identifier")
	cmd.Flags().BoolVar(&opts.replaces, "replaces", false, "List the other packages for which this package is marked as a replacement")
	cmd.Flags().BoolVar(&opts.rinstallIf, "rinstall-if", false, "List other packages whose install_if rules refer to this package")
	cmd.Flags().BoolVarP(&opts.triggers, "triggers", "t", false, "Print active triggers for the package")

	return cmd
}

func runInfo(ctx context.Context, opts *infoOptions, packages []string) error {
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

	apkClient, err := apk.New(ctx, apkOpts...)
	if err != nil {
		return fmt.Errorf("failed to create APK client: %w", err)
	}

	// If no packages specified and not -W (who-owns), list all installed
	if len(packages) == 0 && !opts.whoOwns {
		return listAllInstalled(apkClient, opts, globalOpts.Verbose)
	}

	// Get installed packages
	installed, err := apkClient.GetInstalled()
	if err != nil {
		return fmt.Errorf("failed to get installed packages: %w", err)
	}

	// Default: show description, webpage, and size if no specific flags set
	if !opts.all && !opts.description && !opts.installed && !opts.contents &&
		!opts.provides && !opts.rdepends && !opts.depends && !opts.size &&
		!opts.webpage && !opts.installIf && !opts.license && !opts.replaces &&
		!opts.rinstallIf && !opts.triggers {
		opts.description = true
		opts.webpage = true
		opts.size = true
	}

	// If --all is set, enable all info flags
	if opts.all {
		opts.description = true
		opts.webpage = true
		opts.size = true
		opts.depends = true
		opts.provides = true
		opts.license = true
		opts.replaces = true
		opts.installIf = true
		opts.triggers = true
	}

	// Process each package
	for _, pkgName := range packages {
		// Find package in installed
		var pkg *apk.InstalledPackage
		for _, p := range installed {
			if p.Name == pkgName {
				pkg = p
				break
			}
		}

		if pkg == nil {
			if opts.installed {
				// For -e flag, just exit with error code silently
				return fmt.Errorf("package not installed")
			}
			fmt.Fprintf(os.Stderr, "WARNING: %s: package not installed\n", pkgName)
			continue
		}

		// Print package info
		printPackageInfo(pkg, opts)
	}

	return nil
}

func listAllInstalled(apkClient *apk.APK, opts *infoOptions, verbose int) error {
	installed, err := apkClient.GetInstalled()
	if err != nil {
		return fmt.Errorf("failed to get installed packages: %w", err)
	}

	if opts.installed {
		// For -e flag, just print names
		for _, pkg := range installed {
			fmt.Println(pkg.Name)
		}
	} else if verbose == 0 && !opts.description && !opts.webpage && !opts.size && !opts.depends &&
		!opts.provides && !opts.license && !opts.replaces && !opts.installIf && !opts.contents {
		// No verbose flag and no specific info requested - just print package names
		for _, pkg := range installed {
			fmt.Println(pkg.Name)
		}
	} else if verbose > 0 && !opts.description && !opts.webpage && !opts.size && !opts.depends &&
		!opts.provides && !opts.license && !opts.replaces && !opts.installIf && !opts.contents {
		// With -v flag but no specific info requested - print name-version only
		for _, pkg := range installed {
			fmt.Printf("%s-%s\n", pkg.Name, pkg.Version)
		}
	} else {
		// Print full info for all installed packages
		for _, pkg := range installed {
			printPackageInfo(pkg, opts)
			fmt.Println()
		}
	}

	return nil
}

func printPackageInfo(pkg *apk.InstalledPackage, opts *infoOptions) {
	fmt.Printf("%s-%s", pkg.Name, pkg.Version)

	// Basic info
	if opts.description || opts.all {
		if pkg.Description != "" {
			fmt.Printf(" - %s", pkg.Description)
		}
	}
	fmt.Println()

	// Webpage
	if opts.webpage {
		if pkg.URL != "" {
			fmt.Printf("%s webpage:\n", pkg.Name)
			fmt.Printf("  %s\n", pkg.URL)
		}
	}

	// Size
	if opts.size {
		fmt.Printf("%s installed size:\n", pkg.Name)
		fmt.Printf("  %d\n", pkg.InstalledSize)
	}

	// License
	if opts.license {
		fmt.Printf("%s license:\n", pkg.Name)
		fmt.Printf("  %s\n", pkg.License)
	}

	// Dependencies
	if opts.depends {
		fmt.Printf("%s depends on:\n", pkg.Name)
		if len(pkg.Dependencies) > 0 {
			for _, dep := range pkg.Dependencies {
				fmt.Printf("  %s\n", dep)
			}
		}
	}

	// Provides
	if opts.provides {
		fmt.Printf("%s provides:\n", pkg.Name)
		if len(pkg.Provides) > 0 {
			for _, prov := range pkg.Provides {
				fmt.Printf("  %s\n", prov)
			}
		}
	}

	// Replaces
	if opts.replaces {
		if len(pkg.Replaces) > 0 {
			fmt.Printf("%s replaces:\n", pkg.Name)
			for _, repl := range pkg.Replaces {
				fmt.Printf("  %s\n", repl)
			}
		}
	}

	// Install-if
	if opts.installIf {
		if len(pkg.InstallIf) > 0 {
			fmt.Printf("%s install-if:\n", pkg.Name)
			for _, inst := range pkg.InstallIf {
				fmt.Printf("  %s\n", inst)
			}
		}
	}

	// Contents
	if opts.contents {
		fmt.Printf("%s contains:\n", pkg.Name)
		if len(pkg.Files) > 0 {
			for _, file := range pkg.Files {
				fmt.Printf("  %s\n", file.Name)
			}
		}
	}
}
