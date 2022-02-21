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
	"log"
	"os"

	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/build/types"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func BuildMinirootFS() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "build-minirootfs",
		Short:   "Build a minirootfs image from a YAML configuration file",
		Long:    "Build a minirootfs image from a YAML configuration file",
		Example: `  apko build-minirootfs <config.yaml> <output.tar.gz>`,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return BuildMinirootFSCmd(cmd.Context(), args[0], args[1])
		},
	}

	return cmd
}

func BuildMinirootFSCmd(ctx context.Context, configFile string, outputTarGZ string) error {
	log.Printf("building minirootfs '%s' from config file '%s'", outputTarGZ, configFile)

	ic := types.ImageConfiguration{}
	err := ic.Load(configFile)
	if err != nil {
		return errors.Wrap(err, "failed to load image configuration")
	}

	wd, err := os.MkdirTemp("", "apko-*")
	if err != nil {
		return errors.Wrap(err, "failed to create working directory")
	}
	defer os.RemoveAll(wd)

	bc := build.BuildContext{
		ImageConfiguration: ic,
		WorkDir:            wd,
		TarballPath:        outputTarGZ,
	}

	layerTarGZ, err := bc.BuildLayer()
	if err != nil {
		return errors.Wrap(err, "failed to build layer image")
	}
	log.Printf("wrote minirootfs to %s\n", layerTarGZ)

	return nil
}
