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
	"chainguard.dev/apko/pkg/build/types"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func Publish() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "publish",
		Short: "Build and publish an image",
		Long: `Publish a built image from a YAML configuration file.

It is assumed that you have used "docker login" to store credentials
in a keychain.`,
		Example: `  apko publish <config.yaml> <tag>`,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return PublishCmd(cmd.Context(), args[0], args[1])
		},
	}

	return cmd
}

func PublishCmd(ctx context.Context, configFile string, imageRef string) error {
	log.Printf("building image '%s' from config file '%s'", imageRef, configFile)

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

	bc := build.Context{
		ImageConfiguration: ic,
		WorkDir:            wd,
	}

	layerTarGZ, err := bc.BuildLayer()
	if err != nil {
		return errors.Wrap(err, "failed to build layer image")
	}
	defer os.Remove(layerTarGZ)

	err = oci.PublishImageFromLayer(imageRef, layerTarGZ, bc.ImageConfiguration)
	if err != nil {
		return errors.Wrap(err, "failed to build OCI image")
	}

	return nil
}
