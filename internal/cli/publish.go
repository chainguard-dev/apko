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
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/name"
	coci "github.com/sigstore/cosign/pkg/oci"
	"github.com/sirupsen/logrus"
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
	var debugEnabled bool

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
				build.WithDebugLogging(debugEnabled),
			); err != nil {
				return err
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&imageRefs, "image-refs", "", "path to file where a list of the published image references will be written")
	cmd.Flags().BoolVar(&useProot, "use-proot", false, "use proot to simulate privileged operations")
	cmd.Flags().BoolVar(&useDockerMediaTypes, "use-docker-mediatypes", false, "use Docker mediatypes for image layers/manifest")
	cmd.Flags().BoolVar(&debugEnabled, "debug", false, "enable debug logging")
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
	bc.Logger().Infof(
		"Publishing images for %d architectures: %+v",
		len(bc.ImageConfiguration.Archs),
		bc.ImageConfiguration.Archs,
	)

	// The build context options is sometimes copied in the next functions. Ensure
	// we have the directory defined and created by invoking the function early.
	bc.Options.TempDir()
	defer os.RemoveAll(bc.Options.TempDir())

	bc.Logger().Printf("building tags %v", bc.Options.Tags)

	var errg errgroup.Group
	workDir := bc.Options.WorkDir
	imgs := map[types.Architecture]coci.SignedImage{}

	// This is a hack to skip the SBOM generation during
	// image build. Will be removed when global options are a thing.
	formats := bc.Options.SBOMFormats
	wantSBOM := bc.Options.WantSBOM
	bc.Options.SBOMFormats = []string{}
	bc.Options.WantSBOM = false

	imageTags := []string{}
	if len(bc.ImageConfiguration.Archs) == 1 {
		imageTags = bc.Options.Tags
	}

	var finalDigest name.Digest
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
				finalDigest, img, err = oci.PublishDockerImageFromLayer(layerTarGZ, bc.ImageConfiguration, bc.Options.SourceDateEpoch, arch, bc.Logger(), bc.Options.SBOMPath, bc.Options.SBOMFormats, imageTags...)
				if err != nil {
					return fmt.Errorf("failed to build Docker image for %q: %w", arch, err)
				}
			} else {
				finalDigest, img, err = oci.PublishImageFromLayer(layerTarGZ, bc.ImageConfiguration, bc.Options.SourceDateEpoch, arch, bc.Logger(), bc.Options.SBOMPath, bc.Options.SBOMFormats, imageTags...)
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

	if len(archs) > 1 {
		if bc.Options.UseDockerMediaTypes {
			finalDigest, err = oci.PublishDockerIndex(imgs, logrus.NewEntry(bc.Options.Log), bc.Options.Tags...)
			if err != nil {
				return fmt.Errorf("failed to build Docker index: %w", err)
			}
		} else {
			finalDigest, err = oci.PublishIndex(imgs, logrus.NewEntry(bc.Options.Log), bc.Options.Tags...)
			if err != nil {
				return fmt.Errorf("failed to build OCI index: %w", err)
			}
		}
	}

	bc.Options.SBOMFormats = formats
	sbompath := bc.Options.SBOMPath
	if bc.Options.SBOMPath == "" {
		sbompath = bc.Options.TempDir()
	}

	logrus.Info("Generating Image SBOMs")
	if wantSBOM {
		for arch, img := range imgs {
			bc.Options.WantSBOM = true
			bc.Options.Arch = arch
			bc.Options.TarballPath = filepath.Join(bc.Options.TempDir(), bc.Options.TarballFileName())
			bc.Options.WorkDir = filepath.Join(workDir, arch.ToAPK())

			if err := bc.GenerateImageSBOM(arch, img); err != nil {
				return fmt.Errorf("generating sbom for %s: %w", arch, err)
			}

			if _, err := oci.PostAttachSBOM(
				img, sbompath, bc.Options.SBOMFormats, arch, bc.Logger(), bc.Options.Tags...,
			); err != nil {
				return fmt.Errorf("attaching sboms to %s image: %w", arch, err)
			}
		}
	}

	// If provided, this is the name of the file to write digest referenced into
	if outputRefs != "" {
		//nolint:gosec // Make image ref file readable by non-root
		if err := os.WriteFile(outputRefs, []byte(finalDigest.String()), 0666); err != nil {
			return fmt.Errorf("failed to write digest: %w", err)
		}
	}

	// Write the image digest to STDOUT in order to enable command
	// composition e.g. kn service create --image=$(apko publish ...)
	fmt.Println(finalDigest)

	return nil
}
