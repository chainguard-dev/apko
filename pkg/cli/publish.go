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

	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/build/oci"
	"github.com/spf13/cobra"
)

func Publish() *cobra.Command {
	var imageRefs string
	var useProot bool
	var buildDate string

	cmd := &cobra.Command{
		Use:   "publish",
		Short: "Build and publish an image",
		Long: `Publish a built image from a YAML configuration file.

It is assumed that you have used "docker login" to store credentials
in a keychain.`,
		Example: `  apko publish <config.yaml> <tag...>`,
		Args:    cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			err := PublishCmd(cmd.Context(), imageRefs,
				build.WithConfig(args[0]),
				build.WithProot(useProot),
				build.WithTags(args[1:]...),
				build.WithBuildDate(buildDate),
			)
			if err != nil {
				return err
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&imageRefs, "image-refs", "", "path to file where a list of the published image references will be written")
	cmd.Flags().BoolVar(&useProot, "use-proot", false, "use proot to simulate privileged operations")
	cmd.Flags().StringVar(&buildDate, "build-date", "", "date used for the timestamps of the files inside the image")

	return cmd
}

func PublishCmd(ctx context.Context, outputRefs string, opts ...build.Option) error {
	wd, err := os.MkdirTemp("", "apko-*")
	if err != nil {
		return fmt.Errorf("failed to create working directory: %w", err)
	}
	defer os.RemoveAll(wd)

	bc, err := build.New(wd, opts...)
	if err != nil {
		return err
	}

	log.Printf("building tags %v", bc.Tags)

	layerTarGZ, err := bc.BuildLayer()
	if err != nil {
		return fmt.Errorf("failed to build layer image: %w", err)
	}
	defer os.Remove(layerTarGZ)

	digest, err := oci.PublishImageFromLayer(layerTarGZ, bc.ImageConfiguration, bc.SourceDateEpoch, bc.Tags...)
	if err != nil {
		return fmt.Errorf("failed to build OCI image: %w", err)
	}

	// If provided, this is the name of the file to write digest referenced into
	if outputRefs != "" {
		//nolint:gosec // Make image ref file readable by non-root
		if err := os.WriteFile(outputRefs, []byte(digest.String()), 0666); err != nil {
			return fmt.Errorf("failed to write digest: %w", err)
		}
	}

	// Write the image digest to STDOUT in order to enable command
	// composition e.g. kn service create --image=$(apko publish ...)
	fmt.Println(digest)

	return nil
}
