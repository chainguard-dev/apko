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

	"github.com/chainguard-dev/clog"
	apkfs "github.com/chainguard-dev/go-apk/pkg/fs"
	"github.com/spf13/cobra"

	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/build/types"
)

func buildMinirootFS() *cobra.Command {
	var buildDate string
	var buildArch string
	var sbomPath string

	cmd := &cobra.Command{
		Use:     "build-minirootfs",
		Short:   "Build a minirootfs image from a YAML configuration file",
		Long:    "Build a minirootfs image from a YAML configuration file",
		Example: `  apko build-minirootfs <config.yaml> <output.tar.gz>`,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return BuildMinirootFSCmd(cmd.Context(),
				build.WithConfig(args[0]),
				build.WithTarball(args[1]),
				build.WithBuildDate(buildDate),
				build.WithSBOM(sbomPath),
				build.WithArch(types.ParseArchitecture(buildArch)),
			)
		},
	}

	cmd.Flags().StringVar(&buildDate, "build-date", "", "date used for the timestamps of the files inside the image")
	cmd.Flags().StringVar(&buildArch, "build-arch", runtime.GOARCH, "architecture to build for -- default is Go runtime architecture")
	cmd.Flags().StringVar(&sbomPath, "sbom-path", "", "generate an SBOM")

	return cmd
}

func BuildMinirootFSCmd(ctx context.Context, opts ...build.Option) error {
	log := clog.FromContext(ctx)
	wd, err := os.MkdirTemp("", "apko-*")
	if err != nil {
		return fmt.Errorf("failed to create working directory: %w", err)
	}
	defer os.RemoveAll(wd)

	fs := apkfs.DirFS(wd, apkfs.WithCreateDir())
	bc, err := build.New(ctx, fs, opts...)
	if err != nil {
		return err
	}

	ic := bc.ImageConfiguration()

	if len(ic.Archs) != 0 {
		log.Infof("WARNING: ignoring archs in config, only building for current arch (%s)", bc.Arch())
	}

	log.Infof("building minirootfs '%s'", bc.TarballPath())

	layerTarGZ, _, err := bc.BuildLayer(ctx)
	if err != nil {
		return fmt.Errorf("failed to build layer image: %w", err)
	}
	log.Infof("wrote minirootfs to %s\n", layerTarGZ)

	return nil
}
