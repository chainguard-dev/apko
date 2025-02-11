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
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"github.com/google/go-containerregistry/pkg/v1/layout"
	coci "github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"

	"github.com/chainguard-dev/clog"

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/build/oci"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/sbom"
	"chainguard.dev/apko/pkg/tarfs"
)

func buildCmd() *cobra.Command {
	var withVCS bool
	var buildDate string
	var archstrs []string
	var writeSBOM bool
	var sbomPath string
	var sbomFormats []string
	var extraKeys []string
	var extraBuildRepos []string
	var extraRuntimeRepos []string
	var extraPackages []string
	var rawAnnotations []string
	var cacheDir string
	var offline bool
	var lockfile string
	var includePaths []string
	var ignoreSignatures bool

	cmd := &cobra.Command{
		Use:   "build",
		Short: "Build an image from a YAML configuration file",
		Long: `Build an image from a YAML configuration file.

The generated image is in a format which can be used with the "docker load"
command, e.g.

  # docker load < output.tar

Along the image, apko will generate SBOMs (software bill of materials) describing the image contents.
`,
		Example: `  apko build <config.yaml> <tag> <output.tar|oci-layout-dir/>`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 3 {
				return fmt.Errorf("requires 3 arg: 1 config file, a tag for the image, and an output path")
			}

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

			tmp, err := os.MkdirTemp(os.TempDir(), "apko-temp-*")
			if err != nil {
				return fmt.Errorf("creating tempdir: %w", err)
			}
			defer os.RemoveAll(tmp)

			return BuildCmd(cmd.Context(), args[1], args[2], archs,
				[]string{args[1]},
				writeSBOM,
				sbomPath,
				build.WithConfig(args[0], includePaths),
				build.WithBuildDate(buildDate),
				build.WithSBOM(sbomPath),
				build.WithSBOMFormats(sbomFormats),
				build.WithExtraKeys(extraKeys),
				build.WithExtraBuildRepos(extraBuildRepos),
				build.WithExtraRuntimeRepos(extraRuntimeRepos),
				build.WithExtraPackages(extraPackages),
				build.WithTags(args[1]),
				build.WithVCS(withVCS),
				build.WithAnnotations(annotations),
				build.WithCache(cacheDir, offline, apk.NewCache(true)),
				build.WithLockFile(lockfile),
				build.WithTempDir(tmp),
				build.WithIncludePaths(includePaths),
				build.WithIgnoreSignatures(ignoreSignatures),
			)
		},
	}

	cmd.Flags().BoolVar(&withVCS, "vcs", true, "detect and embed VCS URLs")
	cmd.Flags().StringVar(&buildDate, "build-date", "", "date used for the timestamps of the files inside the image in RFC3339 format")
	cmd.Flags().BoolVar(&writeSBOM, "sbom", true, "generate SBOMs")
	cmd.Flags().StringVar(&sbomPath, "sbom-path", "", "generate SBOMs in dir (defaults to image directory)")
	cmd.Flags().StringSliceVar(&archstrs, "arch", nil, "architectures to build for (e.g., x86_64,ppc64le,arm64) -- default is all, unless specified in config. Can also use 'host' to indicate arch of host this is running on")
	cmd.Flags().StringSliceVarP(&extraKeys, "keyring-append", "k", []string{}, "path to extra keys to include in the keyring")
	cmd.Flags().StringSliceVar(&sbomFormats, "sbom-formats", sbom.DefaultOptions.Formats, "SBOM formats to output")
	cmd.Flags().StringSliceVarP(&extraBuildRepos, "build-repository-append", "b", []string{}, "path to extra repositories to include")
	cmd.Flags().StringSliceVarP(&extraRuntimeRepos, "repository-append", "r", []string{}, "path to extra repositories to include")
	cmd.Flags().StringSliceVarP(&extraPackages, "package-append", "p", []string{}, "extra packages to include")
	cmd.Flags().StringSliceVar(&rawAnnotations, "annotations", []string{}, "OCI annotations to add. Separate with colon (key:value)")
	cmd.Flags().StringVar(&cacheDir, "cache-dir", "", "directory to use for caching apk packages and indexes (default '' means to use system-defined cache directory)")
	cmd.Flags().BoolVar(&offline, "offline", false, "do not use network to fetch packages (cache must be pre-populated)")
	cmd.Flags().StringVar(&lockfile, "lockfile", "", "a path to .lock.json file (e.g. produced by apko lock) that constraints versions of packages to the listed ones (default '' means no additional constraints)")
	cmd.Flags().StringSliceVar(&includePaths, "include-paths", []string{}, "Additional include paths where to look for input files (config, base image, etc.). By default apko will search for paths only in workdir. Include paths may be absolute, or relative. Relative paths are interpreted relative to workdir. For adding extra paths for packages, use --repository-append.")
	cmd.Flags().BoolVar(&ignoreSignatures, "ignore-signatures", false, "ignore repository signature verification")
	return cmd
}

func BuildCmd(ctx context.Context, imageRef, output string, archs []types.Architecture, tags []string, wantSBOM bool, sbomPath string, opts ...build.Option) error {
	log := clog.FromContext(ctx)
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

	if fi, err := os.Stat(output); err == nil && fi.IsDir() {
		// bundle the parts of the image into a tarball
		if _, err := layout.Write(output, idx); err != nil {
			return fmt.Errorf("writing image layout: %w", err)
		}
		log.Debugf("Final image layout at: %s", output)
	} else {
		// bundle the parts of the image into a tarball
		if _, err := oci.BuildIndex(output, idx, append([]string{imageRef}, tags...)); err != nil {
			return fmt.Errorf("bundling image: %w", err)
		}
		log.Debugf("Final index tgz at: %s", output)
	}

	// copy sboms over to the sbomPath target directory
	for _, sbom := range sboms {
		// because os.Rename fails across partitions, we do our own
		if err := rename(sbom.Path, filepath.Join(sbomPath, filepath.Base(sbom.Path))); err != nil {
			return fmt.Errorf("moving sbom: %w", err)
		}
	}
	return nil
}

// buildImage build all of the components of an image in a single working directory.
// Each layer is a separate file, as are config, manifests, index and sbom.
func buildImageComponents(ctx context.Context, workDir string, archs []types.Architecture, opts ...build.Option) (idx coci.SignedImageIndex, sboms []types.SBOM, err error) {
	log := clog.FromContext(ctx)
	ctx, span := otel.Tracer("apko").Start(ctx, "buildImageComponents")
	defer span.End()

	o, ic, err := build.NewOptions(opts...)
	if err != nil {
		return nil, nil, err
	}

	if ic.Contents.BaseImage != nil && o.Lockfile == "" {
		return nil, nil, fmt.Errorf("building with base image is supported only with a lockfile")
	}

	// cases:
	// - archs set: use those archs
	// - archs not set, bc.ImageConfiguration.Archs set: use Config archs
	// - archs not set, bc.ImageConfiguration.Archs not set: use all archs
	switch {
	case len(archs) != 0:
		ic.Archs = archs
	case len(ic.Archs) != 0:
		// do nothing
	default:
		ic.Archs = types.AllArchs
	}
	// save the final set we will build
	log.Debugf("Building images for %d architectures: %+v", len(ic.Archs), ic.Archs)

	// Probe the VCS URL if it is not set and we are asked to do so.
	if o.WithVCS && ic.VCSUrl == "" {
		ic.ProbeVCSUrl(ctx, o.ImageConfigFile)
	}

	// The build context options is sometimes copied in the next functions. Ensure
	// we have the directory defined and created by invoking the function early.

	// workDir, passed to us, is where we will lay out the various image filesystems
	// under it we will have:
	//  <arch>/ - the rootfs for each architecture
	//  image/ - the summary layer files and sboms for each architecture
	// imageDir, created here, is where the final artifacts will be: layer tars, indexes, etc.

	log.Debugf("building tags %v", o.Tags)

	var errg errgroup.Group
	imageDir := filepath.Join(workDir, "image")
	if err := os.MkdirAll(imageDir, 0755); err != nil {
		return nil, nil, fmt.Errorf("unable to create working image directory %s: %w", imageDir, err)
	}
	opts = append(opts, build.WithSBOM(imageDir))

	imgs := map[types.Architecture]coci.SignedImage{}

	mtx := sync.Mutex{}

	// We compute the "build date epoch" of the multi-arch image to be the
	// maximum "build date epoch" of the per-arch images.  If the user has
	// explicitly set SOURCE_DATE_EPOCH, that will always trump this
	// computation.
	multiArchBDE := o.SourceDateEpoch

	configs, _, err := build.LockImageConfiguration(ctx, *ic, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("locking config: %w", err)
	}

	for arch, ic := range configs {
		errg.Go(func() error {
			if arch == "index" {
				return nil
			}

			arch := types.ParseArchitecture(arch)
			log := clog.New(slog.Default().Handler()).With("arch", arch.ToAPK())
			ctx := clog.WithLogger(ctx, log)

			opts := slices.Clone(opts)
			opts = append(opts, build.WithArch(arch), build.WithImageConfiguration(*ic))

			bc, err := build.New(ctx, tarfs.New(), opts...)
			if err != nil {
				return fmt.Errorf("new build for arch %s: %w", arch, err)
			}
			_, layer, err := bc.BuildLayer(ctx)
			if err != nil {
				return fmt.Errorf("building %q layer: %w", arch, err)
			}

			// Compute the "build date epoch" from the packages that were
			// installed.  The "build date epoch" is the MAX of the builddate
			// embedded in the installed APKs.  If SOURCE_DATE_EPOCH is
			// explicitly set by the user, that trumps this.
			// This computation will only affect the timestamp of the image
			// itself and its SBOMs, since the timestamps on files come from the
			// APKs.
			bde, err := bc.GetBuildDateEpoch()
			if err != nil {
				return fmt.Errorf("failed to determine build date epoch: %w", err)
			}

			img, err := oci.BuildImageFromLayer(ctx, bc.BaseImage(), layer, bc.ImageConfiguration(), bde, bc.Arch())
			if err != nil {
				return fmt.Errorf("failed to build OCI image for %q: %w", arch, err)
			}

			var outputs []types.SBOM
			if len(o.SBOMFormats) != 0 {
				outputs, err = bc.GenerateImageSBOM(ctx, arch, img)
				if err != nil {
					return fmt.Errorf("generating sbom for %s: %w", arch, err)
				}
			}

			mtx.Lock()
			defer mtx.Unlock()

			imgs[arch] = img

			if bde.After(multiArchBDE) {
				multiArchBDE = bde
			}

			if len(o.SBOMFormats) != 0 {
				sboms = append(sboms, outputs...)
			}

			return nil
		})
	}
	if err := errg.Wait(); err != nil {
		return nil, nil, err
	}

	// generate the index
	finalDigest, idx, err := oci.GenerateIndex(ctx, *ic, imgs, multiArchBDE)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate OCI index: %w", err)
	}

	opts = append(opts,
		build.WithImageConfiguration(*ic),       // We mutate Archs above.
		build.WithSourceDateEpoch(multiArchBDE), // Maximum child's time.
	)

	o, ic, err = build.NewOptions(opts...)
	if err != nil {
		return nil, nil, err
	}

	if _, err := build.WriteIndex(ctx, o, idx); err != nil {
		return nil, nil, fmt.Errorf("failed to write OCI index: %w", err)
	}

	// the sboms are saved to the same working directory as the image components
	if len(o.SBOMFormats) != 0 {
		files, err := build.GenerateIndexSBOM(ctx, *o, *ic, finalDigest, imgs)
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
