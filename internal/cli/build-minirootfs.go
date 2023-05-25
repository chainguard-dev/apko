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
	"runtime"

	"github.com/spf13/cobra"

	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/iocomb"
	"chainguard.dev/apko/pkg/log"
)

func buildMinirootFS() *cobra.Command {
	var debugEnabled bool
	var quietEnabled bool
	var buildDate string
	var buildArch string
	var sbomPath string
	var logPolicy []string

	cmd := &cobra.Command{
		Use:     "build-minirootfs",
		Short:   "Build a minirootfs image from a YAML configuration file",
		Long:    "Build a minirootfs image from a YAML configuration file",
		Example: `  apko build-minirootfs <config.yaml> <output.tar.gz>`,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
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

			return BuildMinirootFSCmd(cmd.Context(),
				build.WithConfig(args[0]),
				build.WithTarball(args[1]),
				build.WithBuildDate(buildDate),
				build.WithSBOM(sbomPath),
				build.WithArch(types.ParseArchitecture(buildArch)),
				build.WithLogger(logger),
				build.WithDebugLogging(debugEnabled),
			)
		},
	}

	cmd.Flags().BoolVar(&debugEnabled, "debug", false, "enable debug logging")
	cmd.Flags().BoolVar(&quietEnabled, "quiet", false, "disable logging")
	cmd.Flags().StringVar(&buildDate, "build-date", "", "date used for the timestamps of the files inside the image")
	cmd.Flags().StringVar(&buildArch, "build-arch", runtime.GOARCH, "architecture to build for -- default is Go runtime architecture")
	cmd.Flags().StringVar(&sbomPath, "sbom-path", "", "generate an SBOM")
	cmd.Flags().StringSliceVar(&logPolicy, "log-policy", []string{}, "logging policy to use")

	return cmd
}

func BuildMinirootFSCmd(ctx context.Context, opts ...build.Option) error {
	wd, err := os.MkdirTemp("", "apko-*")
	if err != nil {
		return fmt.Errorf("failed to create working directory: %w", err)
	}
	defer os.RemoveAll(wd)

	bc, err := build.New(wd, opts...)
	if err != nil {
		return err
	}

	if err := bc.Refresh(); err != nil {
		return err
	}

	if len(bc.ImageConfiguration.Archs) != 0 {
		bc.Logger().Printf("WARNING: ignoring archs in config, only building for current arch (%s)", bc.Options.Arch)
	}

	bc.Logger().Printf("building minirootfs '%s'", bc.Options.TarballPath)

	layerTarGZ, _, err := bc.BuildLayer()
	if err != nil {
		return fmt.Errorf("failed to build layer image: %w", err)
	}
	bc.Logger().Printf("wrote minirootfs to %s\n", layerTarGZ)

	return nil
}
