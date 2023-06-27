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

package build

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	gzip "golang.org/x/build/pargzip"

	apkimpl "github.com/chainguard-dev/go-apk/pkg/apk"
	apkfs "github.com/chainguard-dev/go-apk/pkg/fs"
	"github.com/chainguard-dev/go-apk/pkg/tarball"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	ggcrtypes "github.com/google/go-containerregistry/pkg/v1/types"
	coci "github.com/sigstore/cosign/v2/pkg/oci"
	"gitlab.alpinelinux.org/alpine/go/repository"
	khash "sigs.k8s.io/release-utils/hash"

	chainguardAPK "chainguard.dev/apko/pkg/apk"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/exec"
	"chainguard.dev/apko/pkg/options"
	"chainguard.dev/apko/pkg/s6"
	"chainguard.dev/apko/pkg/sbom"
	soptions "chainguard.dev/apko/pkg/sbom/options"
)

const indexFile = "index.json"

type buildImplementation struct {
	workdirFS apkfs.FullFS
}

func (di *buildImplementation) Refresh(o *options.Options) (*s6.Context, *exec.Executor, error) {
	o.TarballPath = ""

	hostArch := types.ParseArchitecture(runtime.GOARCH)

	if !o.Arch.Compatible(hostArch) {
		o.Logger().Warnf("%q requires QEMU binfmt emulation to be configured (not compatible with %q)", o.Arch, hostArch)
	}

	executor, err := exec.New(o.WorkDir, o.Logger())
	if err != nil {
		return nil, nil, err
	}

	return s6.New(di.workdirFS, o.Logger()), executor, nil
}

func (di *buildImplementation) BuildTarball(o *options.Options, fsys fs.FS) (string, hash.Hash, hash.Hash, int64, error) {
	var outfile *os.File
	var err error

	if o.TarballPath != "" {
		outfile, err = os.Create(o.TarballPath)
	} else {
		outfile, err = os.Create(filepath.Join(o.TempDir(), o.TarballFileName()))
	}
	if err != nil {
		return "", nil, nil, 0, fmt.Errorf("opening the build context tarball path failed: %w", err)
	}
	o.TarballPath = outfile.Name()
	defer outfile.Close()

	// we use a general override of 0,0 for all files, but the specific overrides, that come from the installed package DB, come later
	tw, err := tarball.NewContext(
		tarball.WithSourceDateEpoch(o.SourceDateEpoch),
	)
	if err != nil {
		return "", nil, nil, 0, fmt.Errorf("failed to construct tarball build context: %w", err)
	}

	digest := sha256.New()

	gzw := gzip.NewWriter(io.MultiWriter(digest, outfile))

	diffid := sha256.New()

	if err := tw.WriteTar(context.TODO(), io.MultiWriter(diffid, gzw), fsys); err != nil {
		return "", nil, nil, 0, fmt.Errorf("failed to generate tarball for image: %w", err)
	}
	if err := gzw.Close(); err != nil {
		return "", nil, nil, 0, fmt.Errorf("closing gzip writer: %w", err)
	}

	stat, err := outfile.Stat()
	if err != nil {
		return "", nil, nil, 0, fmt.Errorf("stat(%q): %w", outfile.Name(), err)
	}

	o.Logger().Infof("built image layer tarball as %s", outfile.Name())
	return outfile.Name(), diffid, digest, stat.Size(), nil
}

// GenerateImageSBOM generates an sbom for an image
func (di *buildImplementation) GenerateImageSBOM(o *options.Options, ic *types.ImageConfiguration, img coci.SignedImage) ([]types.SBOM, error) {
	if len(o.SBOMFormats) == 0 {
		o.Logger().Warnf("skipping SBOM generation")
		return nil, nil
	}

	s := newSBOM(di.workdirFS, o, ic)

	if err := s.ReadLayerTarball(o.TarballPath); err != nil {
		return nil, fmt.Errorf("reading layer tar: %w", err)
	}

	if err := s.ReadReleaseData(); err != nil {
		return nil, fmt.Errorf("getting os-release: %w", err)
	}

	if err := s.ReadPackageIndex(); err != nil {
		return nil, fmt.Errorf("getting installed packages from sbom: %w", err)
	}

	// Get the image digest
	h, err := img.Digest()
	if err != nil {
		return nil, fmt.Errorf("getting %s image digest: %w", o.Arch, err)
	}

	s.Options.ImageInfo.ImageDigest = h.String()
	s.Options.ImageInfo.Arch = o.Arch

	var sboms = make([]types.SBOM, 0)
	files, err := s.Generate()
	if err != nil {
		return nil, fmt.Errorf("generating sbom: %w", err)
	}
	for _, f := range files {
		sboms = append(sboms, types.SBOM{
			Path:   f,
			Format: o.SBOMFormats[0],
			Arch:   o.Arch.String(),
			Digest: h,
		})
	}
	return sboms, nil
}

// GenerateSBOM generates an SBOM for an apko layer
func (di *buildImplementation) GenerateSBOM(o *options.Options, ic *types.ImageConfiguration) error {
	if len(o.SBOMFormats) == 0 {
		o.Logger().Warnf("skipping SBOM generation")
		return nil
	}

	s := newSBOM(di.workdirFS, o, ic)

	if err := s.ReadLayerTarball(o.TarballPath); err != nil {
		return fmt.Errorf("reading layer tar: %w", err)
	}

	if err := s.ReadReleaseData(); err != nil {
		return fmt.Errorf("getting os-release: %w", err)
	}

	if err := s.ReadPackageIndex(); err != nil {
		return fmt.Errorf("getting installed packages from sbom: %w", err)
	}

	s.Options.ImageInfo.Arch = o.Arch

	if _, err := s.Generate(); err != nil {
		return fmt.Errorf("generating SBOMs: %w", err)
	}

	return nil
}

func (di *buildImplementation) InitializeApk(fsys apkfs.FullFS, o *options.Options, ic *types.ImageConfiguration) error {
	apk, err := chainguardAPK.NewWithOptions(fsys, *o)
	if err != nil {
		return err
	}
	return apk.Initialize(ic)
}

func (di *buildImplementation) InstallPackages(fsys apkfs.FullFS, o *options.Options, ic *types.ImageConfiguration) error {
	apk, err := chainguardAPK.NewWithOptions(fsys, *o)
	if err != nil {
		return err
	}
	return apk.Install()
}

func (di *buildImplementation) InstalledPackages(fsys apkfs.FullFS, o *options.Options) ([]*apkimpl.InstalledPackage, error) {
	apk, err := chainguardAPK.NewWithOptions(fsys, *o)
	if err != nil {
		return nil, err
	}
	return apk.GetInstalled()
}

func (di *buildImplementation) ResolvePackages(fsys apkfs.FullFS, o *options.Options, ic *types.ImageConfiguration) (toInstall []*repository.RepositoryPackage, conflicts []string, err error) {
	apk, err := chainguardAPK.NewWithOptions(fsys, *o)
	if err != nil {
		return nil, nil, err
	}
	return apk.ResolvePackages()
}

func (di *buildImplementation) AdditionalTags(fsys apkfs.FullFS, o *options.Options) error {
	at, err := chainguardAPK.AdditionalTags(fsys, *o)
	if err != nil {
		return err
	}
	if at == nil {
		return nil
	}
	o.Tags = append(o.Tags, at...)
	return nil
}

func (di *buildImplementation) BuildImage(
	o *options.Options, ic *types.ImageConfiguration, e *exec.Executor, s6context *s6.Context,
) (fs.FS, error) {
	if err := buildImage(di.workdirFS, di, o, ic, s6context); err != nil {
		return nil, err
	}
	return di.workdirFS, nil
}

// buildImage is a temporary function to make the fakes work.
// This function only installs everything onto a temporary filesystem path
// as defined by o.WorkDir.
// A later stage should add things like busybox symlinks or ldconfig, etc.
// after which it can be loaded into a tarball.
//
// TODO(puerco): In order to have a structure we can mock, we need to split
// image building to its own interface or split out to its own package.
func buildImage(
	fsys apkfs.FullFS, di *buildImplementation, o *options.Options, ic *types.ImageConfiguration,
	s6context *s6.Context,
) error {
	o.Logger().Infof("doing pre-flight checks")
	if err := di.ValidateImageConfiguration(ic); err != nil {
		return fmt.Errorf("failed to validate configuration: %w", err)
	}

	o.Logger().Infof("building image fileystem in %s", o.WorkDir)

	if err := di.InitializeApk(fsys, o, ic); err != nil {
		return fmt.Errorf("initializing apk: %w", err)
	}

	if err := di.InstallPackages(fsys, o, ic); err != nil {
		return fmt.Errorf("installing apk packages: %w", err)
	}

	if err := di.AdditionalTags(fsys, o); err != nil {
		return fmt.Errorf("adding additional tags: %w", err)
	}

	if err := di.MutateAccounts(fsys, o, ic); err != nil {
		return fmt.Errorf("failed to mutate accounts: %w", err)
	}

	if err := di.MutatePaths(fsys, o, ic); err != nil {
		return fmt.Errorf("failed to mutate paths: %w", err)
	}

	if err := di.GenerateOSRelease(fsys, o, ic); err != nil {
		if errors.Is(err, ErrOSReleaseAlreadyPresent) {
			o.Logger().Warnf("did not generate /etc/os-release: %v", err)
		} else {
			return fmt.Errorf("failed to generate /etc/os-release: %w", err)
		}
	}

	if err := di.WriteSupervisionTree(s6context, ic); err != nil {
		return fmt.Errorf("failed to write supervision tree: %w", err)
	}

	// add busybox symlinks
	if err := di.InstallBusyboxLinks(fsys, o); err != nil {
		return err
	}

	// add ldconfig links
	if err := di.InstallLdconfigLinks(fsys); err != nil {
		return err
	}

	// add necessary character devices
	if err := di.InstallCharDevices(fsys); err != nil {
		return err
	}

	o.Logger().Infof("finished building filesystem in %s", o.WorkDir)

	return nil
}

// WriteIndex saves the index file from the given image configuration.
func (di *buildImplementation) WriteIndex(o *options.Options, idx coci.SignedImageIndex) (string, int64, error) {
	outfile := filepath.Join(o.TempDir(), indexFile)

	b, err := idx.RawManifest()
	if err != nil {
		return "", 0, fmt.Errorf("getting raw manifest: %w", err)
	}
	if err := os.WriteFile(outfile, b, 0644); err != nil { //nolint:gosec // this file is fine to be readable
		return "", 0, fmt.Errorf("writing index file: %w", err)
	}

	stat, err := os.Stat(outfile)
	if err != nil {
		return "", 0, fmt.Errorf("stat(%q): %w", outfile, err)
	}

	o.Logger().Infof("built index file as %s", outfile)
	return outfile, stat.Size(), nil
}

func buildPackageList(
	fsys apkfs.FullFS, di *buildImplementation, o *options.Options, ic *types.ImageConfiguration,
) (toInstall []*repository.RepositoryPackage, conflicts []string, err error) {
	o.Logger().Infof("doing pre-flight checks")
	if err := di.ValidateImageConfiguration(ic); err != nil {
		return toInstall, conflicts, fmt.Errorf("failed to validate configuration: %w", err)
	}

	o.Logger().Infof("building apk info in %s", o.WorkDir)

	if err := di.InitializeApk(fsys, o, ic); err != nil {
		return toInstall, conflicts, fmt.Errorf("initializing apk: %w", err)
	}

	if toInstall, conflicts, err = di.ResolvePackages(fsys, o, ic); err != nil {
		return toInstall, conflicts, fmt.Errorf("resolving apk packages: %w", err)
	}
	o.Logger().Infof("finished gathering apk info in %s", o.WorkDir)

	return toInstall, conflicts, err
}

func newSBOM(fsys apkfs.FullFS, o *options.Options, ic *types.ImageConfiguration) *sbom.SBOM {
	s := sbom.NewWithFS(fsys, o.Arch)
	// Parse the image reference
	if len(o.Tags) > 0 {
		tag, err := name.NewTag(o.Tags[0])
		if err == nil {
			s.Options.ImageInfo.Tag = tag.TagStr()
			s.Options.ImageInfo.Name = tag.String()
		} else {
			o.Logger().Errorf("%s parsing tag %s, ignoring", o.Tags[0], err)
		}
	}

	s.Options.ImageInfo.SourceDateEpoch = o.SourceDateEpoch
	s.Options.Formats = o.SBOMFormats
	s.Options.ImageInfo.VCSUrl = ic.VCSUrl

	if o.UseDockerMediaTypes {
		s.Options.ImageInfo.ImageMediaType = ggcrtypes.DockerManifestSchema2
	} else {
		s.Options.ImageInfo.ImageMediaType = ggcrtypes.OCIManifestSchema1
	}

	s.Options.OutputDir = o.TempDir()
	if o.SBOMPath != "" {
		s.Options.OutputDir = o.SBOMPath
	}

	return s
}

func (di *buildImplementation) GenerateIndexSBOM(
	o *options.Options, ic *types.ImageConfiguration,
	indexDigest name.Digest, imgs map[types.Architecture]coci.SignedImage,
) ([]types.SBOM, error) {
	if len(o.SBOMFormats) == 0 {
		o.Logger().Warnf("skipping index SBOM generation")
		return nil, nil
	}

	s := newSBOM(di.workdirFS, o, ic)
	o.Logger().Infof("Generating index SBOM")

	// Add the image digest
	h, err := v1.NewHash(indexDigest.DigestStr())
	if err != nil {
		return nil, errors.New("getting index hash")
	}
	s.Options.ImageInfo.IndexDigest = h

	s.Options.ImageInfo.IndexMediaType = ggcrtypes.OCIImageIndex
	if o.UseDockerMediaTypes {
		s.Options.ImageInfo.IndexMediaType = ggcrtypes.DockerManifestList
	}
	var ext string
	switch o.SBOMFormats[0] {
	case "spdx":
		ext = "spdx.json"
	case "cyclonedx":
		ext = "cdx"
	case "idb":
		ext = "idb"
	}

	// Load the images data into the SBOM generator options
	for arch, i := range imgs {
		sbomHash, err := khash.SHA256ForFile(filepath.Join(s.Options.OutputDir, fmt.Sprintf("sbom-%s.%s", arch.ToAPK(), ext)))
		if err != nil {
			return nil, fmt.Errorf("checksumming %s SBOM: %w", arch, err)
		}

		d, err := i.Digest()
		if err != nil {
			return nil, fmt.Errorf("getting arch image digest: %w", err)
		}

		s.Options.ImageInfo.Images = append(
			s.Options.ImageInfo.Images,
			soptions.ArchImageInfo{
				Digest:     d,
				Arch:       arch,
				SBOMDigest: sbomHash,
			})
	}
	files, err := s.GenerateIndex()
	if err != nil {
		return nil, fmt.Errorf("generating index SBOM: %w", err)
	}
	var sboms = make([]types.SBOM, 0, len(files))
	for _, f := range files {
		sboms = append(sboms, types.SBOM{
			Path:   f,
			Format: o.SBOMFormats[0],
			Digest: h,
		})
	}
	return sboms, nil
}
