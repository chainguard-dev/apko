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
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/name"
	coci "github.com/sigstore/cosign/pkg/oci"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/build/oci"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/sbom"
)

func publish() *cobra.Command {
	var imageRefs string
	var useProot bool
	var useDockerMediaTypes bool
	var buildDate string
	var sbomPath string
	var sbomFormats []string
	var archstrs []string
	var extraKeys []string
	var extraRepos []string

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
				build.WithDockerMediatypes(useDockerMediaTypes),
				build.WithTags(args[1:]...),
				build.WithBuildDate(buildDate),
				build.WithAssertions(build.RequireGroupFile(true), build.RequirePasswdFile(true)),
				build.WithSBOM(sbomPath),
				build.WithSBOMFormats(sbomFormats),
				build.WithExtraKeys(extraKeys),
				build.WithExtraRepos(extraRepos),
			); err != nil {
				return err
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&imageRefs, "image-refs", "", "path to file where a list of the published image references will be written")
	cmd.Flags().BoolVar(&useProot, "use-proot", false, "use proot to simulate privileged operations")
	cmd.Flags().BoolVar(&useDockerMediaTypes, "use-docker-mediatypes", false, "use Docker mediatypes for image layers/manifest")
	cmd.Flags().StringVar(&buildDate, "build-date", "", "date used for the timestamps of the files inside the image")
	cmd.Flags().StringVar(&sbomPath, "sbom-path", "", "generate an SBOM")
	cmd.Flags().StringSliceVar(&archstrs, "arch", nil, "architectures to build for (e.g., x86_64,ppc64le,arm64) -- default is all, unless specified in config.")
	cmd.Flags().StringSliceVarP(&extraKeys, "keyring-append", "k", []string{}, "path to extra keys to include in the keyring")
	cmd.Flags().StringSliceVar(&sbomFormats, "sbom-formats", sbom.DefaultOptions.Formats, "SBOM formats to output")
	cmd.Flags().StringSliceVarP(&extraRepos, "repository-append", "r", []string{}, "path to extra repositories to include")

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

	bc.Logger().Printf("building tags %v", bc.Options.Tags)

	var digest name.Digest
	switch len(bc.ImageConfiguration.Archs) {
	case 0:
		return errors.New("no archs requested")
	case 1:
		bc.Options.Arch = bc.ImageConfiguration.Archs[0]

		if err := bc.Refresh(); err != nil {
			return fmt.Errorf("failed to update build context for %q: %w", bc.Options.Arch, err)
		}

		layerTarGZ, err := bc.BuildLayer()
		if err != nil {
			return fmt.Errorf("failed to build layer image: %w", err)
		}
		defer os.Remove(layerTarGZ)

		if bc.Options.UseDockerMediaTypes {
			digest, _, err = oci.PublishDockerImageFromLayer(layerTarGZ, bc.ImageConfiguration, bc.Options.SourceDateEpoch, bc.Options.Arch, bc.Options.Log, bc.Options.SBOMPath, bc.Options.SBOMFormats, bc.Options.Tags...)
			if err != nil {
				return fmt.Errorf("failed to build Docker image: %w", err)
			}
		} else {
			digest, _, err = oci.PublishImageFromLayer(layerTarGZ, bc.ImageConfiguration, bc.Options.SourceDateEpoch, bc.Options.Arch, bc.Options.Log, bc.Options.SBOMPath, bc.Options.SBOMFormats, bc.Options.Tags...)
			if err != nil {
				return fmt.Errorf("failed to build OCI image: %w", err)
			}
		}

	default:
		var errg errgroup.Group
		workDir := bc.Options.WorkDir
		imgs := map[types.Architecture]coci.SignedImage{}

		for _, arch := range bc.ImageConfiguration.Archs {
			arch := arch
			bc := *bc

			errg.Go(func() error {
				bc.Options.Arch = arch
				bc.Options.WorkDir = filepath.Join(workDir, arch.ToAPK())

				if err := bc.Refresh(); err != nil {
					return fmt.Errorf("failed to update build context for %q: %w", arch, err)
				}

				layerTarGZ, err := bc.BuildLayer()
				if err != nil {
					return fmt.Errorf("failed to build layer image for %q: %w", arch, err)
				}
				// TODO(kaniini): clean up everything correctly for multitag scenario
				// defer os.Remove(layerTarGZ)

				var img coci.SignedImage
				if bc.Options.UseDockerMediaTypes {
					_, img, err = oci.PublishDockerImageFromLayer(layerTarGZ, bc.ImageConfiguration, bc.Options.SourceDateEpoch, arch, bc.Options.Log, bc.Options.SBOMPath, bc.Options.SBOMFormats)
					if err != nil {
						return fmt.Errorf("failed to build Docker image for %q: %w", arch, err)
					}
				} else {
					_, img, err = oci.PublishImageFromLayer(layerTarGZ, bc.ImageConfiguration, bc.Options.SourceDateEpoch, arch, bc.Options.Log, bc.Options.SBOMPath, bc.Options.SBOMFormats)
					if err != nil {
						return fmt.Errorf("failed to build OCI image for %q: %w", arch, err)
					}
				}
				imgs[arch] = img
				return nil
			})
		}

		if err := errg.Wait(); err != nil {
			return err
		}

		if bc.Options.UseDockerMediaTypes {
			digest, err = oci.PublishDockerIndex(imgs, bc.Logger(), bc.Options.Tags...)
			if err != nil {
				return fmt.Errorf("failed to build Docker index: %w", err)
			}
		} else {
			digest, err = oci.PublishIndex(imgs, bc.Logger(), bc.Options.Tags...)
			if err != nil {
				return fmt.Errorf("failed to build OCI index: %w", err)
			}
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
