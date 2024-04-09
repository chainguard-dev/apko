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
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/go-apk/pkg/apk"
	apkfs "github.com/chainguard-dev/go-apk/pkg/fs"
	"github.com/spf13/cobra"
	"golang.org/x/exp/slices"

	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/build/types"
	pkglock "chainguard.dev/apko/pkg/lock"
)

func lock() *cobra.Command {
	return lockInternal("lock", "lock.json", "")
}

func resolve() *cobra.Command {
	return lockInternal(
		"resolve",
		"resolved.json",
		"Please use `lock` command. The `resolve` command will get removed in the future versions.")
}

func lockInternal(cmdName string, extension string, deprecated string) *cobra.Command {
	var extraKeys []string
	var extraRepos []string
	var archstrs []string
	var output string

	cmd := &cobra.Command{
		Use: cmdName,
		// hidden for now until we get some feedback on it.
		Hidden:     true,
		Example:    fmt.Sprintf(`apko %v <config.yaml>`, cmdName),
		Args:       cobra.MinimumNArgs(1),
		Deprecated: deprecated,
		RunE: func(cmd *cobra.Command, args []string) error {
			if output == "" {
				output = fmt.Sprintf("%s."+extension, strings.TrimSuffix(args[0], filepath.Ext(args[0])))
			}

			archs := types.ParseArchitectures(archstrs)

			return LockCmd(
				cmd.Context(),
				output,
				archs,
				[]build.Option{
					build.WithConfig(args[0]),
					build.WithExtraKeys(extraKeys),
					build.WithExtraRepos(extraRepos),
				},
			)
		},
	}

	cmd.Flags().StringSliceVarP(&extraKeys, "keyring-append", "k", []string{}, "path to extra keys to include in the keyring")
	cmd.Flags().StringSliceVarP(&extraRepos, "repository-append", "r", []string{}, "path to extra repositories to include")
	cmd.Flags().StringSliceVar(&archstrs, "arch", nil, "architectures to build for (e.g., x86_64,ppc64le,arm64) -- default is all, unless specified in config. Can also use 'host' to indicate arch of host this is running on")
	cmd.Flags().StringVar(&output, "output", "", "path to file where lock file will be written")

	return cmd
}

func LockCmd(ctx context.Context, output string, archs []types.Architecture, opts []build.Option) error {
	log := clog.FromContext(ctx)
	wd, err := os.MkdirTemp("", "apko-*")
	if err != nil {
		return fmt.Errorf("failed to create working directory: %w", err)
	}
	defer os.RemoveAll(wd)

	o, ic, err := build.NewOptions(opts...)
	if err != nil {
		return err
	}
	// cases:
	// - archs set: use those archs
	// - archs not set, bc.ImageConfiguration.Archs set: use Config archs
	// - archs not set, bc.ImageConfiguration.Archs not set: use all archs
	switch {
	case len(archs) != 0:
		ic.Archs = archs
	case len(ic.Archs) != 0:
		// do nothing
	default:
		ic.Archs = types.AllArchs
	}
	// save the final set we will build
	archs = ic.Archs
	log.Infof("Determining packages for %d architectures: %+v", len(ic.Archs), ic.Archs)

	// The build context options is sometimes copied in the next functions. Ensure
	// we have the directory defined and created by invoking the function early.
	defer os.RemoveAll(o.TempDir())

	lock := pkglock.Lock{
		Version: "v1",
		Config: &pkglock.Config{
			Name:         o.ImageConfigFile,
			DeepChecksum: o.ImageConfigChecksum,
		},
		Contents: pkglock.LockContents{
			Packages:     []pkglock.LockPkg{},
			Repositories: []pkglock.LockRepo{},
			Keyrings:     []pkglock.LockKeyring{},
		},
	}

	for _, keyring := range ic.Contents.Keyring {
		lock.Contents.Keyrings = append(lock.Contents.Keyrings, pkglock.LockKeyring{
			Name: stripURLScheme(keyring),
			URL:  keyring,
		})
	}

	// TODO: If the archs can't agree on package versions (e.g., arm builds are ahead of x86) then we should fail instead of producing inconsistent locks.
	for _, arch := range archs {
		arch := arch
		log := clog.New(slog.Default().Handler()).With("arch", arch.ToAPK())
		ctx = clog.WithLogger(ctx, log)

		// working directory for this architecture
		wd := filepath.Join(wd, arch.ToAPK())
		bopts := append(slices.Clone(opts), build.WithArch(arch))
		fs := apkfs.DirFS(wd, apkfs.WithCreateDir())
		bc, err := build.New(ctx, fs, bopts...)
		if err != nil {
			return err
		}

		resolvedPkgs, err := bc.ResolveWithBase(ctx)

		if err != nil {
			return fmt.Errorf("failed to get package list for image: %w", err)
		}

		for _, rpkg := range resolvedPkgs {
			lockPkg := pkglock.LockPkg{
				Name:         rpkg.Package.Name,
				URL:          rpkg.Package.URL(),
				Architecture: rpkg.Package.Arch,
				Version:      rpkg.Package.Version,
				Control: pkglock.LockPkgRangeAndChecksum{
					Range:    fmt.Sprintf("bytes=%d-%d", rpkg.SignatureSize, rpkg.ControlSize-1),
					Checksum: "sha1-" + base64.StdEncoding.EncodeToString(rpkg.ControlHash),
				},
				Data: pkglock.LockPkgRangeAndChecksum{
					Range:    fmt.Sprintf("bytes=%d-%d", rpkg.ControlSize, rpkg.DataSize),
					Checksum: "sha256-" + base64.StdEncoding.EncodeToString(rpkg.DataHash),
				},
				Checksum: rpkg.Package.ChecksumString(),
			}

			if rpkg.SignatureSize != 0 {
				lockPkg.Signature = pkglock.LockPkgRangeAndChecksum{
					Range:    fmt.Sprintf("bytes=0-%d", rpkg.SignatureSize-1),
					Checksum: "sha1-" + base64.StdEncoding.EncodeToString(rpkg.SignatureHash),
				}
			}

			lock.Contents.Packages = append(lock.Contents.Packages, lockPkg)
		}
		for _, repositoryURI := range ic.Contents.Repositories {
			repo := apk.Repository{URI: fmt.Sprintf("%s/%s", repositoryURI, arch.ToAPK())}
			lock.Contents.Repositories = append(lock.Contents.Repositories, pkglock.LockRepo{
				Name:         stripURLScheme(repo.URI),
				URL:          repo.IndexURI(),
				Architecture: arch.ToAPK(),
			})
		}
	}
	return lock.SaveToFile(output)
}

func stripURLScheme(url string) string {
	return strings.TrimPrefix(
		strings.TrimPrefix(url, "https://"),
		"http://",
	)
}
