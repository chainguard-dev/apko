// Copyright 2022, 2023 Chainguard, Inc.
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

	apkfs "github.com/chainguard-dev/go-apk/pkg/fs"
	"github.com/spf13/cobra"

	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/build/types"
)

func showPackages() *cobra.Command {
	var extraKeys []string
	var extraRepos []string
	var archstrs []string

	cmd := &cobra.Command{
		Use:   "show-packages",
		Short: "Show the packages and versions that would be installed by a configuration",
		Long: `Show the packages and versions that would be installed by a configuration.
The result is similar to the first stages of a build, but does not actuall install anything.
`,
		Example: `  apko show-packages <config.yaml>`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			archs := types.ParseArchitectures(archstrs)
			return ShowPackagesCmd(cmd.Context(), archs,
				build.WithConfig(args[0]),
				build.WithExtraKeys(extraKeys),
				build.WithExtraRepos(extraRepos),
			)
		},
	}

	cmd.Flags().StringSliceVarP(&extraKeys, "keyring-append", "k", []string{}, "path to extra keys to include in the keyring")
	cmd.Flags().StringSliceVarP(&extraRepos, "repository-append", "r", []string{}, "path to extra repositories to include")
	cmd.Flags().StringSliceVar(&archstrs, "arch", nil, "architectures to build for (e.g., x86_64,ppc64le,arm64) -- default is all, unless specified in config. Can also use 'host' to indicate arch of host this is running on")

	return cmd
}

func ShowPackagesCmd(ctx context.Context, archs []types.Architecture, opts ...build.Option) error {
	wd, err := os.MkdirTemp("", "apko-*")
	if err != nil {
		return fmt.Errorf("failed to create working directory: %w", err)
	}
	defer os.RemoveAll(wd)

	fsys := apkfs.DirFS(wd, apkfs.WithCreateDir())

	bc, err := build.New(fsys, opts...)
	if err != nil {
		return err
	}

	if err := bc.Refresh(); err != nil {
		return err
	}

	// cases:
	// - archs set: use those archs
	// - archs not set, bc.ImageConfiguration.Archs set: use Config archs
	// - archs not set, bc.ImageConfiguration.Archs not set: use all archs
	switch {
	case len(archs) != 0:
		bc.ImageConfiguration.Archs = archs
	case len(bc.ImageConfiguration.Archs) != 0:
		// do nothing
	default:
		bc.ImageConfiguration.Archs = types.AllArchs
	}
	// save the final set we will build
	archs = bc.ImageConfiguration.Archs
	bc.Logger().Infof(
		"Determining packages for %d architectures: %+v",
		len(bc.ImageConfiguration.Archs),
		bc.ImageConfiguration.Archs,
	)

	// The build context options is sometimes copied in the next functions. Ensure
	// we have the directory defined and created by invoking the function early.
	bc.Options.TempDir()
	defer os.RemoveAll(bc.Options.TempDir())

	for _, arch := range archs {
		arch := arch
		// working directory for this architecture
		wd := filepath.Join(wd, arch.ToAPK())
		fsys := apkfs.DirFS(wd, apkfs.WithCreateDir())
		bc, err := build.New(fsys, opts...)
		if err != nil {
			return err
		}

		// we do not generate SBOMs for each arch, only possibly for final image
		bc.Options.SBOMFormats = []string{}
		bc.Options.WantSBOM = false
		bc.ImageConfiguration.Archs = archs

		bc.Options.Arch = arch

		if err := bc.Refresh(); err != nil {
			return fmt.Errorf("failed to update build context for %q: %w", arch, err)
		}

		pkgs, _, err := bc.BuildPackageList()
		if err != nil {
			return fmt.Errorf("failed to get package list for image: %w", err)
		}
		fmt.Println(arch)
		for _, pkg := range pkgs {
			fmt.Printf("  %s %s\n", pkg.Name, pkg.Version)
		}
		fmt.Println()
	}
	return nil
}
