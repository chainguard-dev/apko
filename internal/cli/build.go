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
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/name"
	coci "github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/build/oci"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/iocomb"
	"chainguard.dev/apko/pkg/log"
	"chainguard.dev/apko/pkg/sbom"
)

func buildCmd() *cobra.Command {
	var useDockerMediaTypes bool
	var debugEnabled bool
	var quietEnabled bool
	var withVCS bool
	var buildDate string
	var archstrs []string
	var writeSBOM bool
	var sbomPath string
	var sbomFormats []string
	var extraKeys []string
	var extraRepos []string
	var buildOptions []string
	var logPolicy []string
	var rawAnnotations []string

	cmd := &cobra.Command{
		Use:   "build",
		Short: "Build an image from a YAML configuration file",
		Long: `Build an image from a YAML configuration file.

The generated image is in a format which can be used with the "docker load"
command, e.g.

  # docker load < output.tar

Along the image, apko will generate CycloneDX and SPDX SBOMs (software
bill of materials) describing the image contents.
`,
		Example: `  apko build <config.yaml> <tag> <output.tar>`,
		Args:    cobra.ExactArgs(3),
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

			// TODO(kaniini): Print warning when multi-arch build is requested
			// and ignored by the build system.
			archs := types.ParseArchitectures(archstrs)
			annotations, err := parseAnnotations(rawAnnotations)
			if err != nil {
				return fmt.Errorf("parsing annotations from command line: %w", err)
			}

			if !writeSBOM {
				sbomFormats = []string{}
			}
			return BuildCmd(cmd.Context(), args[1], args[2], archs,
				build.WithConfig(args[0]),
				build.WithDockerMediatypes(useDockerMediaTypes),
				build.WithBuildDate(buildDate),
				build.WithAssertions(build.RequireGroupFile(true), build.RequirePasswdFile(true)),
				build.WithSBOM(sbomPath),
				build.WithSBOMFormats(sbomFormats),
				build.WithExtraKeys(extraKeys),
				build.WithTags(args[1]),
				build.WithExtraRepos(extraRepos),
				build.WithLogger(logger),
				build.WithDebugLogging(debugEnabled),
				build.WithVCS(withVCS),
				build.WithAnnotations(annotations),
				build.WithBuildOptions(buildOptions),
			)
		},
	}

	cmd.Flags().BoolVar(&useDockerMediaTypes, "use-docker-mediatypes", false, "use Docker mediatypes for image layers/manifest")
	cmd.Flags().BoolVar(&debugEnabled, "debug", false, "enable debug logging")
	cmd.Flags().BoolVar(&quietEnabled, "quiet", false, "disable logging")
	cmd.Flags().BoolVar(&withVCS, "vcs", true, "detect and embed VCS URLs")
	cmd.Flags().StringVar(&buildDate, "build-date", "", "date used for the timestamps of the files inside the image in RFC3339 format")
	cmd.Flags().BoolVar(&writeSBOM, "sbom", true, "generate SBOMs")
	cmd.Flags().StringVar(&sbomPath, "sbom-path", "", "generate SBOMs in dir (defaults to image directory)")
	cmd.Flags().StringSliceVar(&archstrs, "arch", nil, "architectures to build for (e.g., x86_64,ppc64le,arm64) -- default is all, unless specified in config. Can also use 'host' to indicate arch of host this is running on")
	cmd.Flags().StringSliceVarP(&extraKeys, "keyring-append", "k", []string{}, "path to extra keys to include in the keyring")
	cmd.Flags().StringSliceVar(&sbomFormats, "sbom-formats", sbom.DefaultOptions.Formats, "SBOM formats to output")
	cmd.Flags().StringSliceVarP(&extraRepos, "repository-append", "r", []string{}, "path to extra repositories to include")
	cmd.Flags().StringSliceVar(&buildOptions, "build-option", []string{}, "build options to enable")
	cmd.Flags().StringSliceVar(&logPolicy, "log-policy", []string{}, "logging policy to use")
	cmd.Flags().StringSliceVar(&rawAnnotations, "annotations", []string{}, "OCI annotations to add. Separate with colon (key:value)")

	return cmd
}

func BuildCmd(ctx context.Context, imageRef, outputTarGZ string, archs []types.Architecture, opts ...build.Option) error {
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

	if bc.Options.SBOMPath == "" {
		dir, err := filepath.Abs(outputTarGZ)
		if err != nil {
			return fmt.Errorf("resolving output file path: %w", err)
		}
		bc.Options.SBOMPath = filepath.Dir(dir)
	}

	// cases:
	// - archs set: use those archs
	// - archs not set, bc.ImageConfiguration.Archs set: use Config archs
	// - archs not set, bc.ImageConfiguration.Archs not set: use all archs
	switch {
	case len(archs) != 0:
		bc.ImageConfiguration.Archs = archs
	case len(bc.ImageConfiguration.Archs) != 0:
		// do nothing
	default:
		bc.ImageConfiguration.Archs = types.AllArchs
	}
	// save the final set we will build
	archs = bc.ImageConfiguration.Archs
	bc.Logger().Infof(
		"Building images for %d architectures: %+v",
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
	contexts := map[types.Architecture]*build.Context{}
	imageTars := map[types.Architecture]string{}

	// This is a hack to skip the SBOM generation during
	// image build. Will be removed when global options are a thing.
	formats := bc.Options.SBOMFormats
	wantSBOM := bc.Options.WantSBOM
	bc.Options.SBOMFormats = []string{}
	bc.Options.WantSBOM = false

	var finalDigest name.Digest

	defer func() {
		for _, f := range imageTars {
			_ = os.Remove(f)
		}
	}()

	// We compute the "build date epoch" of the multi-arch image to be the
	// maximum "build date epoch" of the per-arch images.  If the user has
	// explicitly set SOURCE_DATE_EPOCH, that will always trump this
	// computation.
	multiArchBDE := bc.Options.SourceDateEpoch

	for _, arch := range archs {
		arch := arch
		// working directory for this architecture
		wd := filepath.Join(workDir, arch.ToAPK())
		bc, err := build.New(wd, opts...)
		if err != nil {
			return err
		}

		// we do not generate SBOMs for each arch, only possibly for final image
		bc.Options.SBOMFormats = []string{}
		bc.Options.WantSBOM = false
		bc.ImageConfiguration.Archs = archs

		// save the build context for later
		contexts[arch] = bc

		errg.Go(func() error {
			bc.Options.Arch = arch
			bc.Options.WorkDir = wd

			if err := bc.Refresh(); err != nil {
				return fmt.Errorf("failed to update build context for %q: %w", arch, err)
			}

			layerTarGZ, layer, err := bc.BuildLayer()
			if err != nil {
				return fmt.Errorf("failed to build layer image: %w", err)
			}

			// Compute the "build date epoch" from the packages that were
			// installed.  The "build date epoch" is the MAX of the builddate
			// embedded in the installed APKs.  If SOURCE_DATE_EPOCH is
			// explicitly set by the user, that trumps this.
			// This computation will only affect the timestamp of the image
			// itself and its SBOMs, since the timestamps on files come from the
			// APKs.
			if bc.Options.SourceDateEpoch, err = bc.GetBuildDateEpoch(); err != nil {
				return fmt.Errorf("failed to determine build date epoch: %w", err)
			}
			if bc.Options.SourceDateEpoch.After(multiArchBDE) {
				multiArchBDE = bc.Options.SourceDateEpoch
			}

			imageTars[arch] = layerTarGZ
			img, err := oci.BuildImageFromLayer(
				layer, bc.ImageConfiguration, bc.Logger(), bc.Options)
			if err != nil {
				return fmt.Errorf("failed to build OCI image: %w", err)
			}
			imgs[arch] = img
			return nil
		})
	}
	if err := errg.Wait(); err != nil {
		return err
	}
	bc.Options.SourceDateEpoch = multiArchBDE

	bc.Options.SBOMFormats = formats
	sbomPath := bc.Options.SBOMPath

	if wantSBOM {
		logrus.Info("Generating arch image SBOMs")
		var g errgroup.Group
		for arch, img := range imgs {
			arch, img := arch, img
			bc := contexts[arch]

			// override the SBOM options
			bc.Options.SBOMFormats = formats
			bc.Options.WantSBOM = true
			bc.Options.SBOMPath = sbomPath

			g.Go(func() error {
				if err := bc.GenerateImageSBOM(arch, img); err != nil {
					return fmt.Errorf("generating sbom for %s: %w", arch, err)
				}
				return nil
			})
		}

		if err := g.Wait(); err != nil {
			return err
		}
	}

	// finally generate the tar.gz file that includes all of the arch images and an index
	finalDigest, err = oci.BuildIndex(outputTarGZ, bc.ImageConfiguration, imgs, bc.Options.Tags, bc.Logger())
	if err != nil {
		return fmt.Errorf("failed to build index: %w", err)
	}
	if wantSBOM {
		if err := bc.GenerateIndexSBOM(finalDigest, imgs); err != nil {
			return fmt.Errorf("generating index SBOM: %w", err)
		}
	}

	bc.Logger().Infof(
		"Final index tgz at: %s", outputTarGZ,
	)

	return nil
}
