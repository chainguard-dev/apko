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

package build

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/google/go-containerregistry/pkg/name"
	v1tar "github.com/google/go-containerregistry/pkg/v1/tarball"

	chainguardAPK "chainguard.dev/apko/pkg/apk"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/exec"
	apkofs "chainguard.dev/apko/pkg/fs"
	"chainguard.dev/apko/pkg/options"
	"chainguard.dev/apko/pkg/s6"
	"chainguard.dev/apko/pkg/sbom"
	"chainguard.dev/apko/pkg/tarball"
)

//counterfeiter:generate . buildImplementation

type buildImplementation interface {
	Refresh(*options.Options) (*s6.Context, *exec.Executor, error)
	BuildTarball(*options.Options) (string, error)
	GenerateSBOM(*options.Options) error
	InstallBusyboxSymlinks(*options.Options, *exec.Executor) error
	InitializeApk(*options.Options, *types.ImageConfiguration) error
	MutateAccounts(*options.Options, *types.ImageConfiguration) error
	MutatePaths(*options.Options, *types.ImageConfiguration) error
	GenerateOSRelease(*options.Options, *types.ImageConfiguration) error
	ValidateImageConfiguration(*types.ImageConfiguration) error
	BuildImage(*options.Options, *types.ImageConfiguration, *exec.Executor, *s6.Context) error
	WriteSupervisionTree(*s6.Context, *types.ImageConfiguration) error
}

type defaultBuildImplementation struct{}

func (di *defaultBuildImplementation) Refresh(o *options.Options) (*s6.Context, *exec.Executor, error) {
	o.TarballPath = ""

	hostArch := types.ParseArchitecture(runtime.GOARCH)

	execOpts := []exec.Option{exec.WithProot(o.UseProot)}
	if o.UseProot && !o.Arch.Compatible(hostArch) {
		o.Logger().Debugf("%q requires QEMU (not compatible with %q)", o.Arch, hostArch)
		execOpts = append(execOpts, exec.WithQemu(o.Arch.ToQEmu()))
	}

	executor, err := exec.New(o.WorkDir, o.Logger(), execOpts...)
	if err != nil {
		return nil, nil, err
	}

	return s6.New(o.WorkDir, o.Logger()), executor, nil
}

func (di *defaultBuildImplementation) BuildTarball(o *options.Options) (string, error) {
	var outfile *os.File
	var err error

	if o.TarballPath != "" {
		outfile, err = os.Create(o.TarballPath)
	} else {
		outfile, err = os.Create(filepath.Join(o.TempDir(), o.TarballFileName()))
	}
	if err != nil {
		return "", fmt.Errorf("opening the build context tarball path failed: %w", err)
	}
	o.TarballPath = outfile.Name()
	defer outfile.Close()

	tw, err := tarball.NewContext(tarball.WithSourceDateEpoch(o.SourceDateEpoch))
	if err != nil {
		return "", fmt.Errorf("failed to construct tarball build context: %w", err)
	}

	if err := tw.WriteArchive(outfile, apkofs.DirFS(o.WorkDir)); err != nil {
		return "", fmt.Errorf("failed to generate tarball for image: %w", err)
	}

	o.Logger().Infof("built image layer tarball as %s", outfile.Name())
	return outfile.Name(), nil
}

// GenerateSBOM runs the sbom generation
func (di *defaultBuildImplementation) GenerateSBOM(o *options.Options) error {
	if len(o.SBOMFormats) == 0 {
		o.Logger().Warnf("skipping SBOM generation")
		return nil
	}
	o.Logger().Infof("generating SBOM")

	// TODO(puerco): Split GenerateSBOM into context implementation
	s := sbom.NewWithWorkDir(o.WorkDir, o.Arch)

	v1Layer, err := v1tar.LayerFromFile(o.TarballPath)
	if err != nil {
		return fmt.Errorf("failed to create OCI layer from tar.gz: %w", err)
	}

	digest, err := v1Layer.Digest()
	if err != nil {
		return fmt.Errorf("could not calculate layer digest: %w", err)
	}

	// Parse the image reference
	if len(o.Tags) > 0 {
		tag, err := name.NewTag(o.Tags[0])
		if err != nil {
			return fmt.Errorf("parsing tag %s: %w", o.Tags[0], err)
		}
		s.Options.ImageInfo.Tag = tag.TagStr()
		s.Options.ImageInfo.Name = tag.String()
	}

	s.Options.ImageInfo.ImageDigest = o.ImageDigest

	// Generate the packages externally as we may
	// move the package reader somewhere else
	packages, err := s.ReadPackageIndex()
	if err != nil {
		return fmt.Errorf("getting installed packages from sbom: %w", err)
	}
	s.Options.ImageInfo.Arch = o.Arch
	s.Options.ImageInfo.LayerDigest = digest.String()
	s.Options.ImageInfo.SourceDateEpoch = o.SourceDateEpoch
	s.Options.OutputDir = o.SBOMPath
	s.Options.Packages = packages
	s.Options.Formats = o.SBOMFormats

	if _, err := s.Generate(); err != nil {
		return fmt.Errorf("generating SBOMs: %w", err)
	}

	return nil
}

func (di *defaultBuildImplementation) InitializeApk(o *options.Options, ic *types.ImageConfiguration) error {
	apk := chainguardAPK.NewWithOptions(*o)
	return apk.Initialize(ic)
}

func (di *defaultBuildImplementation) BuildImage(
	o *options.Options, ic *types.ImageConfiguration, e *exec.Executor, s6context *s6.Context,
) error {
	return buildImage(di, o, ic, e, s6context)
}

// buildImage is a temporary function to make the fakes work.
// TODO(puerco): In order to have a structure we can mock, we need to split
// image building to its own interface or split out to its own package.
func buildImage(
	di buildImplementation, o *options.Options, ic *types.ImageConfiguration,
	e *exec.Executor, s6context *s6.Context,
) error {
	o.Logger().Infof("doing pre-flight checks")
	if err := di.ValidateImageConfiguration(ic); err != nil {
		return fmt.Errorf("failed to validate configuration: %w", err)
	}

	o.Logger().Infof("building image fileystem in %s", o.WorkDir)

	if err := di.InitializeApk(o, ic); err != nil {
		return fmt.Errorf("initializing apk: %w", err)
	}

	if err := di.MutateAccounts(o, ic); err != nil {
		return fmt.Errorf("failed to mutate accounts: %w", err)
	}

	if err := di.MutatePaths(o, ic); err != nil {
		return fmt.Errorf("failed to mutate paths: %w", err)
	}

	// maybe install busybox symlinks
	if err := di.InstallBusyboxSymlinks(o, e); err != nil {
		return fmt.Errorf("failed to install busybox symlinks: %w", err)
	}

	if err := di.GenerateOSRelease(o, ic); err != nil {
		return fmt.Errorf("failed to generate /etc/os-release: %w", err)
	}

	if err := di.WriteSupervisionTree(s6context, ic); err != nil {
		return fmt.Errorf("failed to write supervision tree: %w", err)
	}

	o.Logger().Infof("finished building filesystem in %s", o.WorkDir)

	return nil
}
