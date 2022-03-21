// Copyright 2022 Chainguard, Inc.
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
	"log"
	"os"
	"runtime"

	"github.com/spf13/cobra"

	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/build/types"
)

func BuildMinirootFS() *cobra.Command {
	var useProot bool
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
				build.WithProot(useProot),
				build.WithBuildDate(buildDate),
				build.WithSBOM(sbomPath),
				build.WithArch(types.ParseArchitecture(buildArch)),
			)
		},
	}

	cmd.Flags().BoolVar(&useProot, "use-proot", false, "use proot to simulate privileged operations")
	cmd.Flags().StringVar(&buildDate, "build-date", "", "date used for the timestamps of the files inside the image")
	cmd.Flags().StringVar(&buildArch, "build-arch", runtime.GOARCH, "architecture to build for -- default is Go runtime architecture")
	cmd.Flags().StringVar(&sbomPath, "sbom-path", "", "generate an SBOM")

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
		log.Printf("WARNING: ignoring archs in config, only building for current arch (%s)", bc.Arch)
	}

	log.Printf("building minirootfs '%s'", bc.TarballPath)

	layerTarGZ, err := bc.BuildLayer()
	if err != nil {
		return fmt.Errorf("failed to build layer image: %w", err)
	}
	log.Printf("wrote minirootfs to %s\n", layerTarGZ)

	return nil
}
