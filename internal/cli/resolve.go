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
	pkglock "chainguard.dev/apko/pkg/lock"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	apkfs "github.com/chainguard-dev/go-apk/pkg/fs"
	"github.com/spf13/cobra"
	"golang.org/x/exp/slices"

	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/iocomb"
	"chainguard.dev/apko/pkg/log"
)

func resolve() *cobra.Command {
	var extraKeys []string
	var extraRepos []string
	var archstrs []string
	var output string

	var logPolicy []string
	var debugEnabled bool
	var quietEnabled bool

	cmd := &cobra.Command{
		Use: "resolve",
		// hidden for now until we get some feedback on it.
		Hidden:  true,
		Example: `apko resolve <config.yaml>`,
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if output == "" {
				output = fmt.Sprintf("%s.resolved.json", strings.TrimSuffix(args[0], filepath.Ext(args[0])))
			}

			if len(logPolicy) == 0 {
				if quietEnabled {
					logPolicy = []string{"builtin:discard"}
				} else {
					logPolicy = []string{"builtin:stderr"}
				}
			}

			logWriter, err := iocomb.Combine(logPolicy)
			if err != nil {
				return fmt.Errorf("invalid logging policy: %w", err)
			}
			logger := log.NewLogger(logWriter)

			archs := types.ParseArchitectures(archstrs)

			return ResolveCmd(
				cmd.Context(),
				output,
				archs,
				[]build.Option{
					build.WithLogger(logger),
					build.WithConfig(args[0]),
					build.WithExtraKeys(extraKeys),
					build.WithExtraRepos(extraRepos),
					build.WithDebugLogging(debugEnabled),
				},
			)
		},
	}

	cmd.Flags().StringSliceVarP(&extraKeys, "keyring-append", "k", []string{}, "path to extra keys to include in the keyring")
	cmd.Flags().StringSliceVarP(&extraRepos, "repository-append", "r", []string{}, "path to extra repositories to include")
	cmd.Flags().StringSliceVar(&archstrs, "arch", nil, "architectures to build for (e.g., x86_64,ppc64le,arm64) -- default is all, unless specified in config. Can also use 'host' to indicate arch of host this is running on")
	cmd.Flags().StringVar(&output, "output", "", "path to file where lock file will be written")
	cmd.Flags().StringSliceVar(&logPolicy, "log-policy", []string{}, "logging policy to use")
	cmd.Flags().BoolVar(&debugEnabled, "debug", false, "enable debug logging")
	cmd.Flags().BoolVar(&quietEnabled, "quiet", false, "disable logging")

	return cmd
}

func ResolveCmd(ctx context.Context, output string, archs []types.Architecture, opts []build.Option) error {
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
	o.Logger().Infof("Determining packages for %d architectures: %+v", len(ic.Archs), ic.Archs)

	// The build context options is sometimes copied in the next functions. Ensure
	// we have the directory defined and created by invoking the function early.
	defer os.RemoveAll(o.TempDir())

	lock := pkglock.Lock{
		Version: "v1",
		Contents: pkglock.LockContents{
			Packages:     []pkglock.LockPkg{},
			Repositories: []pkglock.LockRepo{},
			Keyrings:     []pkglock.LockKeyring{},
		},
	}

	repositories := map[string]bool{}

	for _, keyring := range ic.Contents.Keyring {
		lock.Contents.Keyrings = append(lock.Contents.Keyrings, pkglock.LockKeyring{
			Name: stripURLScheme(keyring),
			URL:  keyring,
		})
	}

	// TODO: If the archs can't agree on package versions (e.g., arm builds are ahead of x86) then we should fail instead of producing inconsistent locks.
	for _, arch := range archs {
		arch := arch
		// working directory for this architecture
		wd := filepath.Join(wd, arch.ToAPK())
		bopts := append(slices.Clone(opts), build.WithArch(arch))
		fs := apkfs.DirFS(wd, apkfs.WithCreateDir())
		bc, err := build.New(ctx, fs, bopts...)
		if err != nil {
			return err
		}

		resolvedPkgs, err := bc.Resolve(ctx)

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
			}

			if rpkg.SignatureSize != 0 {
				lockPkg.Signature = pkglock.LockPkgRangeAndChecksum{
					Range:    fmt.Sprintf("bytes=0-%d", rpkg.SignatureSize-1),
					Checksum: "sha1-" + base64.StdEncoding.EncodeToString(rpkg.SignatureHash),
				}
			}

			lock.Contents.Packages = append(lock.Contents.Packages, lockPkg)

			if _, ok := repositories[rpkg.Package.Repository().URI]; !ok {
				lock.Contents.Repositories = append(lock.Contents.Repositories, pkglock.LockRepo{
					Name:         stripURLScheme(rpkg.Package.Repository().URI),
					URL:          rpkg.Package.Repository().IndexURI(),
					Architecture: arch.ToAPK(),
				})
				repositories[rpkg.Package.Repository().URI] = true
			}
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
