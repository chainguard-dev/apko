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
	"os"
	"path/filepath"
	"runtime"

	gzip "golang.org/x/build/pargzip"

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

func (bc *Context) Refresh() error {
	bc.Options.TarballPath = ""

	arch := bc.Options.Arch
	hostArch := types.ParseArchitecture(runtime.GOARCH)

	if !bc.Options.Arch.Compatible(hostArch) {
		bc.Logger().Warnf("%q requires QEMU binfmt emulation to be configured (not compatible with %q)", arch, hostArch)
	}

	executor, err := exec.New(bc.Logger())
	if err != nil {
		return err
	}
	bc.executor = executor

	bc.s6 = s6.New(bc.fs, bc.Logger())
	return nil
}

func (bc *Context) BuildTarball() (string, hash.Hash, hash.Hash, int64, error) {
	var outfile *os.File
	var err error

	if tp := bc.Options.TarballPath; tp != "" {
		outfile, err = os.Create(tp)
	} else {
		outfile, err = os.Create(filepath.Join(bc.Options.TempDir(), bc.Options.TarballFileName()))
	}
	if err != nil {
		return "", nil, nil, 0, fmt.Errorf("opening the build context tarball path failed: %w", err)
	}
	bc.Options.TarballPath = outfile.Name()

	defer outfile.Close()

	// we use a general override of 0,0 for all files, but the specific overrides, that come from the installed package DB, come later
	tw, err := tarball.NewContext(
		tarball.WithSourceDateEpoch(bc.Options.SourceDateEpoch),
	)
	if err != nil {
		return "", nil, nil, 0, fmt.Errorf("failed to construct tarball build context: %w", err)
	}

	digest := sha256.New()

	gzw := gzip.NewWriter(io.MultiWriter(digest, outfile))

	diffid := sha256.New()

	if err := tw.WriteTar(context.TODO(), io.MultiWriter(diffid, gzw), bc.fs); err != nil {
		return "", nil, nil, 0, fmt.Errorf("failed to generate tarball for image: %w", err)
	}
	if err := gzw.Close(); err != nil {
		return "", nil, nil, 0, fmt.Errorf("closing gzip writer: %w", err)
	}

	stat, err := outfile.Stat()
	if err != nil {
		return "", nil, nil, 0, fmt.Errorf("stat(%q): %w", outfile.Name(), err)
	}

	bc.Logger().Infof("built image layer tarball as %s", outfile.Name())
	return outfile.Name(), diffid, digest, stat.Size(), nil
}

// GenerateImageSBOM generates an sbom for an image
func (bc *Context) GenerateImageSBOM(arch types.Architecture, img coci.SignedImage) error {
	bc.Options.Arch = arch

	if len(bc.Options.SBOMFormats) == 0 {
		bc.Logger().Warnf("skipping SBOM generation")
		return nil
	}

	// TODO(jonjohnsonjr): Rewrite this.
	s := newSBOM(bc.fs, &bc.Options, &bc.ImageConfiguration)

	if err := s.ReadLayerTarball(bc.Options.TarballPath); err != nil {
		return fmt.Errorf("reading layer tar: %w", err)
	}

	if err := s.ReadReleaseData(); err != nil {
		return fmt.Errorf("getting os-release: %w", err)
	}

	if err := s.ReadPackageIndex(); err != nil {
		return fmt.Errorf("getting installed packages from sbom: %w", err)
	}

	// Get the image digest
	h, err := img.Digest()
	if err != nil {
		return fmt.Errorf("getting %s image digest: %w", arch, err)
	}

	s.Options.ImageInfo.ImageDigest = h.String()
	s.Options.ImageInfo.Arch = arch

	if _, err := s.Generate(); err != nil {
		return fmt.Errorf("generating SBOMs: %w", err)
	}

	return nil
}

// GenerateSBOM generates an SBOM for an apko layer
func (bc *Context) GenerateSBOM() error {
	if len(bc.Options.SBOMFormats) == 0 {
		bc.Logger().Warnf("skipping SBOM generation")
		return nil
	}

	s := newSBOM(bc.fs, &bc.Options, &bc.ImageConfiguration)

	if err := s.ReadLayerTarball(bc.Options.TarballPath); err != nil {
		return fmt.Errorf("reading layer tar: %w", err)
	}

	if err := s.ReadReleaseData(); err != nil {
		return fmt.Errorf("getting os-release: %w", err)
	}

	if err := s.ReadPackageIndex(); err != nil {
		return fmt.Errorf("getting installed packages from sbom: %w", err)
	}

	s.Options.ImageInfo.Arch = bc.Options.Arch

	if _, err := s.Generate(); err != nil {
		return fmt.Errorf("generating SBOMs: %w", err)
	}

	return nil
}

func (bc *Context) AdditionalTags() error {
	at, err := chainguardAPK.AdditionalTags(bc.fs, bc.Options)
	if err != nil {
		return err
	}
	if at == nil {
		return nil
	}
	bc.Options.Tags = append(bc.Options.Tags, at...)
	return nil
}

// buildImage is a temporary function to make the fakes work.
// This function only installs everything onto a temporary filesystem.
// A later stage should add things like busybox symlinks or ldconfig, etc.
// after which it can be loaded into a tarball.
func (bc *Context) buildImage() error {
	bc.Logger().Infof("building image fileystem in")

	if err := bc.apk.Install(); err != nil {
		return fmt.Errorf("installing apk packages: %w", err)
	}

	if err := bc.AdditionalTags(); err != nil {
		return fmt.Errorf("adding additional tags: %w", err)
	}

	if err := bc.MutateAccounts(); err != nil {
		return fmt.Errorf("failed to mutate accounts: %w", err)
	}

	if err := bc.MutatePaths(); err != nil {
		return fmt.Errorf("failed to mutate paths: %w", err)
	}

	if err := bc.GenerateOSRelease(); err != nil {
		if errors.Is(err, ErrOSReleaseAlreadyPresent) {
			bc.Logger().Warnf("did not generate /etc/os-release: %v", err)
		} else {
			return fmt.Errorf("failed to generate /etc/os-release: %w", err)
		}
	}

	if err := bc.WriteSupervisionTree(); err != nil {
		return fmt.Errorf("failed to write supervision tree: %w", err)
	}

	// add busybox symlinks
	if err := bc.InstallBusyboxLinks(); err != nil {
		return err
	}

	// add ldconfig links
	if err := bc.InstallLdconfigLinks(); err != nil {
		return err
	}

	// add necessary character devices
	if err := bc.InstallCharDevices(); err != nil {
		return err
	}

	bc.Logger().Infof("finished building filesystem")

	return nil
}

func (bc *Context) BuildPackageList() (toInstall []*repository.RepositoryPackage, conflicts []string, err error) {
	bc.Logger().Infof("resolving apk packages")

	if toInstall, conflicts, err = bc.apk.ResolvePackages(); err != nil {
		return toInstall, conflicts, fmt.Errorf("resolving apk packages: %w", err)
	}
	bc.Logger().Infof("finished gathering apk info")

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

func (bc *Context) GenerateIndexSBOM(indexDigest name.Digest, imgs map[types.Architecture]coci.SignedImage) error {
	if len(bc.Options.SBOMFormats) == 0 {
		bc.Logger().Warnf("skipping index SBOM generation")
		return nil
	}

	s := newSBOM(bc.fs, &bc.Options, &bc.ImageConfiguration)
	bc.Logger().Infof("Generating index SBOM")

	// Add the image digest
	h, err := v1.NewHash(indexDigest.DigestStr())
	if err != nil {
		return errors.New("getting index hash")
	}
	s.Options.ImageInfo.IndexDigest = h

	s.Options.ImageInfo.IndexMediaType = ggcrtypes.OCIImageIndex
	if bc.Options.UseDockerMediaTypes {
		s.Options.ImageInfo.IndexMediaType = ggcrtypes.DockerManifestList
	}
	var ext string
	switch bc.Options.SBOMFormats[0] {
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
			return fmt.Errorf("checksumming %s SBOM: %w", arch, err)
		}

		d, err := i.Digest()
		if err != nil {
			return fmt.Errorf("getting arch image digest: %w", err)
		}

		s.Options.ImageInfo.Images = append(
			s.Options.ImageInfo.Images,
			soptions.ArchImageInfo{
				Digest:     d,
				Arch:       arch,
				SBOMDigest: sbomHash,
			})
	}

	if _, err := s.GenerateIndex(); err != nil {
		return fmt.Errorf("generting index SBOM: %w", err)
	}

	return nil
}
