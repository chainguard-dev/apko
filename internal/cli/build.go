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
	"runtime"
	"strings"

	"github.com/spf13/pflag"

	"github.com/spf13/cobra"

	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/build/oci"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/sbom"
)

func buildCmd() *cobra.Command {
	var useDockerMediaTypes bool
	var debugEnabled bool
	var withVCS bool
	var buildDate string
	var buildArch []string
	var writeSBOM bool
	var sbomPath string
	var sbomFormats []string
	var extraKeys []string
	var extraRepos []string

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
			// TODO(kaniini): Print warning when multi-arch build is requested
			// and ignored by the build system.
			var ba string
			if len(buildArch) > 0 {
				ba = buildArch[0]
			}

			if !writeSBOM {
				sbomFormats = []string{}
			}
			return BuildCmd(cmd.Context(), args[1], args[2],
				build.WithConfig(args[0]),
				build.WithDockerMediatypes(useDockerMediaTypes),
				build.WithBuildDate(buildDate),
				build.WithAssertions(build.RequireGroupFile(true), build.RequirePasswdFile(true)),
				build.WithSBOM(sbomPath),
				build.WithSBOMFormats(sbomFormats),
				build.WithExtraKeys(extraKeys),
				build.WithTags(args[1]),
				build.WithExtraRepos(extraRepos),
				build.WithArch(types.ParseArchitecture(ba)),
				build.WithDebugLogging(debugEnabled),
				build.WithVCS(withVCS),
			)
		},
	}

	cmd.Flags().BoolVar(&useDockerMediaTypes, "use-docker-mediatypes", false, "use Docker mediatypes for image layers/manifest")
	cmd.Flags().BoolVar(&debugEnabled, "debug", false, "enable debug logging")
	cmd.Flags().BoolVar(&withVCS, "vcs", true, "detect and embed VCS URLs")
	cmd.Flags().StringVar(&buildDate, "build-date", "", "date used for the timestamps of the files inside the image in RFC3339 format")
	cmd.Flags().BoolVar(&writeSBOM, "sbom", true, "generate SBOMs")
	cmd.Flags().StringVar(&sbomPath, "sbom-path", "", "generate SBOMs in dir (defaults to image directory)")
	_ = cmd.Flags().MarkDeprecated("build-arch", "use --arch instead")
	cmd.Flags().StringSliceVar(&buildArch, "arch", []string{runtime.GOARCH}, "architecture to build for -- default is Go runtime architecture")
	cmd.Flags().StringSliceVarP(&extraKeys, "keyring-append", "k", []string{}, "path to extra keys to include in the keyring")
	cmd.Flags().StringSliceVar(&sbomFormats, "sbom-formats", sbom.DefaultOptions.Formats, "SBOM formats to output")
	cmd.Flags().StringSliceVarP(&extraRepos, "repository-append", "r", []string{}, "path to extra repositories to include")

	cmd.Flags().SetNormalizeFunc(normalizeBuildArch)
	return cmd
}

func normalizeBuildArch(f *pflag.FlagSet, name string) pflag.NormalizedName {
	if strings.EqualFold(name, "build-arch") {
		name = "arch"
	}
	return pflag.NormalizedName(name)
}

func BuildCmd(ctx context.Context, imageRef, outputTarGZ string, opts ...build.Option) error {
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

	if len(bc.ImageConfiguration.Archs) != 0 {
		bc.Logger().Printf("WARNING: ignoring archs in config, only building for current arch (%s)", bc.Options.Arch)
	}

	bc.Logger().Printf("building image '%s'", imageRef)

	layerTarGZ, err := bc.BuildLayer()
	if err != nil {
		return fmt.Errorf("failed to build layer image: %w", err)
	}

	defer os.Remove(layerTarGZ)

	if err := bc.GenerateSBOM(); err != nil {
		return fmt.Errorf("generating SBOMs: %w", err)
	}

	if err := oci.BuildImageTarballFromLayer(
		imageRef, layerTarGZ, outputTarGZ, bc.ImageConfiguration, bc.Logger(), bc.Options); err != nil {
		return fmt.Errorf("failed to build OCI image: %w", err)
	}

	return nil
}
