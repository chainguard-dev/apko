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
	"chainguard.dev/apko/pkg/build/oci"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func Build() *cobra.Command {
	var useProot bool

	cmd := &cobra.Command{
		Use:   "build",
		Short: "Build an image from a YAML configuration file",
		Long: `Build an image from a YAML configuration file.

The generated image is in a format which can be used with the "docker load"
command, e.g.

  # docker load < output.tar`,
		Example: `  apko build <config.yaml> <tag> <output.tar>`,
		Args:    cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			return BuildCmd(cmd.Context(), args[1], args[2],
				build.WithConfig(args[0]),
				build.WithProot(useProot),
			)
		},
	}

	cmd.Flags().BoolVar(&useProot, "use-proot", false, "use proot to simulate privileged operations")

	return cmd
}

func BuildCmd(ctx context.Context, imageRef string, outputTarGZ string, opts ...build.Option) error {
	wd, err := os.MkdirTemp("", "apko-*")
	if err != nil {
		return errors.Wrap(err, "failed to create working directory")
	}
	defer os.RemoveAll(wd)

	bc := build.Context{
		WorkDir: wd,
	}

	for _, opt := range opts {
		if err := opt(&bc); err != nil {
			return err
		}
	}

	log.Printf("building image '%s'", imageRef)

	layerTarGZ, err := bc.BuildLayer()
	if err != nil {
		return errors.Wrap(err, "failed to build layer image")
	}
	defer os.Remove(layerTarGZ)

	err = oci.BuildImageTarballFromLayer(imageRef, layerTarGZ, outputTarGZ, bc.ImageConfiguration)
	if err != nil {
		return errors.Wrap(err, "failed to build OCI image")
	}

	return nil
}
