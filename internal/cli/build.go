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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	coci "github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"

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
	var extraPackages []string
	var buildOptions []string
	var logPolicy []string
	var rawAnnotations []string
	var cacheDir string

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
				[]string{args[1]},
				writeSBOM,
				sbomPath,
				logger,
				build.WithLogger(logger),
				build.WithConfig(args[0]),
				build.WithDockerMediatypes(useDockerMediaTypes),
				build.WithBuildDate(buildDate),
				build.WithAssertions(build.RequireGroupFile(true), build.RequirePasswdFile(true)),
				build.WithSBOM(sbomPath),
				build.WithSBOMFormats(sbomFormats),
				build.WithExtraKeys(extraKeys),
				build.WithExtraRepos(extraRepos),
				build.WithExtraPackages(extraPackages),
				build.WithTags(args[1]),
				build.WithDebugLogging(debugEnabled),
				build.WithVCS(withVCS),
				build.WithAnnotations(annotations),
				build.WithBuildOptions(buildOptions),
				build.WithCacheDir(cacheDir),
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
	cmd.Flags().StringSliceVarP(&extraPackages, "package-append", "p", []string{}, "extra packages to include")
	_ = cmd.Flags().MarkDeprecated("build-option", "use --package-append instead")
	cmd.Flags().StringSliceVar(&logPolicy, "log-policy", []string{}, "logging policy to use")
	cmd.Flags().StringSliceVar(&rawAnnotations, "annotations", []string{}, "OCI annotations to add. Separate with colon (key:value)")
	cmd.Flags().StringVar(&cacheDir, "cache-dir", "", "directory to use for caching apk packages and indexes (default '' means to use system-defined cache directory)")

	return cmd
}

func BuildCmd(ctx context.Context, imageRef, outputTar string, archs []types.Architecture, tags []string, wantSBOM bool, sbomPath string, logger log.Logger, opts ...build.Option) error {
	wd, err := os.MkdirTemp("", "apko-*")
	if err != nil {
		return fmt.Errorf("failed to create working directory: %w", err)
	}
	defer os.RemoveAll(wd)

	// build all of the components in the working directory
	idx, sboms, err := buildImageComponents(ctx, wd, archs, opts...)
	if err != nil {
		return err
	}

	// bundle the parts of the image into a tarball
	if _, err := oci.BuildIndex(outputTar, idx, append([]string{imageRef}, tags...), logger); err != nil {
		return fmt.Errorf("bundling image: %w", err)
	}

	// copy sboms over to the sbomPath target directory
	for _, sbom := range sboms {
		// because os.Rename fails across partitions, we do our own
		if err := rename(sbom.Path, filepath.Join(sbomPath, filepath.Base(sbom.Path))); err != nil {
			return fmt.Errorf("moving sbom: %w", err)
		}
	}

	logrus.Infof(
		"Final image at: %s", outputTarOrLayoutDir,
	)

	return nil
}

// buildImage build all of the components of an image in a single working directory.
// Each layer is a separate file, as are config, manifests, index and sbom.
func buildImageComponents(ctx context.Context, wd string, archs []types.Architecture, opts ...build.Option) (idx coci.SignedImageIndex, sboms []types.SBOM, err error) {
	bc, err := build.New(wd, opts...)
	if err != nil {
		return nil, nil, err
	}

	if err := bc.Refresh(); err != nil {
		return nil, nil, err
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

	// workDir, passed to us, is where we will lay out the various image filesystems
	// under it we will have:
	//  <arch>/ - the rootfs for each architecture
	//  image/ - the summary layer files and sboms for each architecture
	// imageDir, created here, is where the final artifacts will be: layer tars, indexes, etc.

	bc.Logger().Printf("building tags %v", bc.Options.Tags)

	var errg errgroup.Group
	workDir := wd
	imageDir := filepath.Join(workDir, "image")
	if err := os.MkdirAll(imageDir, 0755); err != nil {
		return nil, nil, fmt.Errorf("unable to create working image directory %s: %w", imageDir, err)
	}

	imgs := map[types.Architecture]coci.SignedImage{}
	contexts := map[types.Architecture]*build.Context{}
	imageTars := map[types.Architecture]string{}

	// This is a hack to skip the SBOM generation during
	// image build. Will be removed when global options are a thing.
	formats := bc.Options.SBOMFormats
	wantSBOM := bc.Options.WantSBOM
	bc.Options.SBOMFormats = []string{}
	bc.Options.WantSBOM = false

	mtx := sync.Mutex{}

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
			return nil, nil, err
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
			bc.Options.TarballPath = filepath.Join(imageDir, bc.Options.TarballFileName())

			layerTarGZ, layer, err := bc.BuildLayer()
			if err != nil {
				return fmt.Errorf("failed to build layer image for %q: %w", arch, err)
			}
			imageTars[arch] = layerTarGZ

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

			img, err := oci.BuildImageFromLayer(
				layer, bc.ImageConfiguration, bc.Options.SourceDateEpoch, bc.Options.Arch, bc.Logger())
			if err != nil {
				return fmt.Errorf("failed to build OCI image for %q: %w", arch, err)
			}
			mtx.Lock()
			imgs[arch] = img
			mtx.Unlock()

			return nil
		})
	}
	if err := errg.Wait(); err != nil {
		return nil, nil, err
	}

	// generate the index
	finalDigest, idx, err := oci.GenerateIndex(ctx, bc.ImageConfiguration, imgs)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate OCI index: %w", err)
	}
	if _, _, err := bc.WriteIndex(idx); err != nil {
		return nil, nil, fmt.Errorf("failed to write OCI index: %w", err)
	}

	bc.Options.SourceDateEpoch = multiArchBDE

	bc.Options.SBOMFormats = formats

	// the sboms are saved to the same working directory as the image components
	if wantSBOM {
		logrus.Info("Generating arch image SBOMs")
		var (
			g   errgroup.Group
			mtx sync.Mutex
		)
		for arch, img := range imgs {
			arch, img := arch, img
			bc := contexts[arch]

			// override the SBOM options
			bc.Options.WantSBOM = true
			bc.Options.SBOMFormats = formats
			bc.Options.SBOMPath = imageDir

			g.Go(func() error {
				outputs, err := bc.GenerateImageSBOM(arch, img)
				if err != nil {
					return fmt.Errorf("generating sbom for %s: %w", arch, err)
				}
				mtx.Lock()
				sboms = append(sboms, outputs...)
				mtx.Unlock()
				return nil
			})
		}

		if err := g.Wait(); err != nil {
			return nil, nil, err
		}
		bc.Options.WantSBOM = true
		bc.Options.SBOMFormats = formats
		bc.Options.SBOMPath = imageDir
		files, err := bc.GenerateIndexSBOM(finalDigest, imgs)
		if err != nil {
			return nil, nil, fmt.Errorf("generating index SBOM: %w", err)
		}
		sboms = append(sboms, files...)
	}

	return idx, sboms, nil
}

// rename just like os.Rename, but does a copy and delete if the rename fails
func rename(from, to string) error {
	err := os.Rename(from, to)
	if err == nil {
		return nil
	}
	// we can handle cross-device rename errors
	if !errors.Is(err, unix.EXDEV) {
		return err
	}
	f1, err := os.Open(from)
	if err != nil {
		return err
	}
	defer f1.Close()
	f2, err := os.Create(to)
	if err != nil {
		return err
	}
	defer f2.Close()
	_, err = io.Copy(f2, f1)
	if err != nil {
		return err
	}
	return os.Remove(from)
}
