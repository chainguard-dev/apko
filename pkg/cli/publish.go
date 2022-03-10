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
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/build/oci"
	"chainguard.dev/apko/pkg/build/types"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

func Publish() *cobra.Command {
	var imageRefs string
	var useProot bool
	var buildDate string
	var sbomPath string
	var archstrs []string

	cmd := &cobra.Command{
		Use:   "publish",
		Short: "Build and publish an image",
		Long: `Publish a built image from a YAML configuration file.

It is assumed that you have used "docker login" to store credentials
in a keychain.`,
		Example: `  apko publish <config.yaml> <tag...>`,
		Args:    cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			archs := types.ParseArchitectures(archstrs)
			if err := PublishCmd(cmd.Context(), imageRefs, archs,
				build.WithConfig(args[0]),
				build.WithProot(useProot),
				build.WithTags(args[1:]...),
				build.WithBuildDate(buildDate),
				build.WithSBOM(sbomPath),
			); err != nil {
				return err
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&imageRefs, "image-refs", "", "path to file where a list of the published image references will be written")
	cmd.Flags().BoolVar(&useProot, "use-proot", false, "use proot to simulate privileged operations")
	cmd.Flags().StringVar(&buildDate, "build-date", "", "date used for the timestamps of the files inside the image")
	cmd.Flags().StringVar(&sbomPath, "sbom-path", "", "generate an SBOM")
	cmd.Flags().StringSliceVar(&archstrs, "arch", nil, "architectures to build for (e.g., x86_64,ppc64le,arm64) -- default is all, unless specified in config.")

	return cmd
}

func PublishCmd(ctx context.Context, outputRefs string, archs []types.Architecture, opts ...build.Option) error {
	wd, err := os.MkdirTemp("", "apko-*")
	if err != nil {
		return fmt.Errorf("failed to create working directory: %w", err)
	}
	defer os.RemoveAll(wd)

	bc, err := build.New(wd, opts...)
	if err != nil {
		return err
	}

	if len(archs) == 0 {
		archs = types.AllArchs
	}
	if len(bc.ImageConfiguration.Archs) == 0 {
		bc.ImageConfiguration.Archs = archs
	}

	log.Printf("building tags %v", bc.Tags)

	var digest name.Digest
	switch len(bc.ImageConfiguration.Archs) {
	case 0:
		return errors.New("no archs requested")
	case 1:
		bc.Arch = bc.ImageConfiguration.Archs[0]
		layerTarGZ, err := bc.BuildLayer()
		if err != nil {
			return fmt.Errorf("failed to build layer image: %w", err)
		}
		defer os.Remove(layerTarGZ)

		digest, _, err = oci.PublishImageFromLayer(layerTarGZ, bc.ImageConfiguration, bc.SourceDateEpoch, bc.Arch, bc.Tags...)
		if err != nil {
			return fmt.Errorf("failed to build OCI image: %w", err)
		}
	default:
		var errg errgroup.Group
		imgs := map[types.Architecture]v1.Image{}
		workDir := bc.WorkDir
		for _, arch := range archs {
			arch := arch
			bc := *bc // Don't modify the original build context.

			errg.Go(func() error {
				bc.Arch = arch
				bc.WorkDir = filepath.Join(workDir, arch.ToAPK())
				layerTarGZ, err := bc.BuildLayer()
				if err != nil {
					return fmt.Errorf("failed to build layer image for %q: %w", arch, err)
				}
				defer os.Remove(layerTarGZ)

				_, img, err := oci.PublishImageFromLayer(layerTarGZ, bc.ImageConfiguration, bc.SourceDateEpoch, arch)
				if err != nil {
					return fmt.Errorf("failed to build OCI image for %q: %w", arch, err)
				}
				imgs[arch] = img
				return nil
			})
		}
		if err := errg.Wait(); err != nil {
			return err
		}
		digest, err = oci.PublishIndex(imgs, bc.Tags...)
		if err != nil {
			return fmt.Errorf("failed to build OCI index: %w", err)
		}
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
