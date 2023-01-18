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
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	ggcrtypes "github.com/google/go-containerregistry/pkg/v1/types"
	coci "github.com/sigstore/cosign/pkg/oci"
	"golang.org/x/sys/unix"
	"sigs.k8s.io/release-utils/hash"

	chainguardAPK "chainguard.dev/apko/pkg/apk"
	memfs "chainguard.dev/apko/pkg/apk/impl/memfs"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/exec"
	apkofs "chainguard.dev/apko/pkg/fs"
	"chainguard.dev/apko/pkg/options"
	"chainguard.dev/apko/pkg/s6"
	"chainguard.dev/apko/pkg/sbom"
	soptions "chainguard.dev/apko/pkg/sbom/options"
	"chainguard.dev/apko/pkg/tarball"
)

//counterfeiter:generate . buildImplementation

type buildImplementation interface {
	// Refresh initialize build, set options, and get a jail and emulation executor and s6 supervisor config
	Refresh(*options.Options) (*s6.Context, *exec.Executor, error)
	// BuildTarball build from the layout in a working directory to an OCI image layer tarball
	BuildTarball(*options.Options, []tar.Header) (string, error)
	// GenerateSBOM generate a software-bill-of-materials for the image
	GenerateSBOM(*options.Options, *types.ImageConfiguration) error
	// InitializeApk do all of the steps to set up apk for installing packages in the working directory
	InitializeApk(*options.Options, *types.ImageConfiguration) error
	// MutateAccounts set up the user accounts and groups in the working directory
	MutateAccounts(*options.Options, *types.ImageConfiguration) error
	// MutatePaths set permissions and ownership on files based on the ImageConfiguration
	MutatePaths(*options.Options, *types.ImageConfiguration) ([]tar.Header, error)
	// GenerateOSRelase generate /etc/os-release in the working directory
	GenerateOSRelease(*options.Options, *types.ImageConfiguration) error
	// ValidateImageConfiguration check that the supplied ImageConfiguration is valid
	ValidateImageConfiguration(*types.ImageConfiguration) error
	// BuildImage based on the ImageConfiguration, run all of the steps to generate the laid out paths in the working directory
	BuildImage(*options.Options, *types.ImageConfiguration, *exec.Executor, *s6.Context) ([]tar.Header, error)
	// WriteSupervisionTree insert the configuration files and binaries in the working directory for s6 to operate
	WriteSupervisionTree(*s6.Context, *types.ImageConfiguration) error
	// GenerateIndexSBOM generate an SBOM for the index
	GenerateIndexSBOM(*options.Options, *types.ImageConfiguration, name.Digest, map[types.Architecture]coci.SignedImage) error
	// GenerateImageSBOM generate an SBOM for the image contents
	GenerateImageSBOM(*options.Options, *types.ImageConfiguration, coci.SignedImage) error
	// AdditionalTags generate additional tags for apk packages
	AdditionalTags(*options.Options) error
}

type defaultBuildImplementation struct{}

func (di *defaultBuildImplementation) Refresh(o *options.Options) (*s6.Context, *exec.Executor, error) {
	o.TarballPath = ""

	hostArch := types.ParseArchitecture(runtime.GOARCH)

	if !o.Arch.Compatible(hostArch) {
		o.Logger().Warnf("%q requires QEMU binfmt emulation to be configured (not compatible with %q)", o.Arch, hostArch)
	}

	executor, err := exec.New(o.WorkDir, o.Logger())
	if err != nil {
		return nil, nil, err
	}

	return s6.New(o.WorkDir, o.Logger()), executor, nil
}

func (di *defaultBuildImplementation) BuildTarball(o *options.Options, overrides []tar.Header) (string, error) {
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

	// ensure that the tar entries for homedirs have correct permissions and ownership
	var overrideHeaders = make([]tar.Header, 0, 10)

	apk, err := chainguardAPK.NewWithOptions(*o)
	if err != nil {
		return "", fmt.Errorf("could not acquire apk filesystem: %w", err)
	}
	pkgs, err := apk.GetInstalled()
	if err != nil {
		return "", fmt.Errorf("could not get installed packages: %w", err)
	}
	// go through each package, and ensure that each file has the correct permissions and ownership
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			overrideHeaders = append(overrideHeaders, tar.Header{
				Typeflag: file.Typeflag,
				Name:     file.Name,
				Mode:     file.Mode,
				Uid:      file.Uid,
				Gid:      file.Gid,
			})
		}
	}

	// get the proper permissions for the initdb files
	files := apk.ListInitFiles()
	for _, file := range files {
		overrideHeaders = append(overrideHeaders, tar.Header{
			Name: file.Name,
			Mode: file.Mode,
			Uid:  0,
			Gid:  0,
		})
	}

	// get the proper permissions for the base directories
	baseDirs := []string{"/tmp", "/proc", "/dev", "/var", "/lib", "/etc"}
	for _, d := range baseDirs {
		overrideHeaders = append(overrideHeaders, tar.Header{
			Name: d,
			Mode: 0o755,
			Uid:  0,
			Gid:  0,
		})
	}

	// overrides from the mutations
	overrideHeaders = append(overrideHeaders, overrides...)

	// we use a general override of 0,0 for all files, but the specific overrides, that come from the installed package DB, come later
	tw, err := tarball.NewContext(
		tarball.WithSourceDateEpoch(o.SourceDateEpoch),
		tarball.WithOverrideUIDGID(0, 0),
		tarball.WithOverrideUname("root"),
		tarball.WithOverrideGname("root"),
		tarball.WithOverridePerms(overrideHeaders),
	)
	if err != nil {
		return "", fmt.Errorf("failed to construct tarball build context: %w", err)
	}

	// add busybox symlinks in a dedicated readlinkFS
	workdirFS := apkofs.DirFS(o.WorkDir)
	busyboxLinksFS, err := installBusyboxLinks(workdirFS)
	if err != nil {
		return "", err
	}
	ldconfigLinksFS, err := installLdconfigLinks(workdirFS)
	if err != nil {
		return "", err
	}
	charDevicesFS, err := installCharDevices(workdirFS)
	if err != nil {
		return "", err
	}
	// merge the various filesystems to provide a single one, which can be fed to the tar archive writer
	mergedFS, err := mergeFS(workdirFS, busyboxLinksFS, ldconfigLinksFS, charDevicesFS)
	if err != nil {
		return "", fmt.Errorf("failed to merge filesystems: %w", err)
	}
	if err := tw.WriteArchive(outfile, mergedFS); err != nil {
		return "", fmt.Errorf("failed to generate tarball for image: %w", err)
	}

	o.Logger().Infof("built image layer tarball as %s", outfile.Name())
	return outfile.Name(), nil
}

// GenerateImageSBOM generates an sbom for an image
func (di *defaultBuildImplementation) GenerateImageSBOM(o *options.Options, ic *types.ImageConfiguration, img coci.SignedImage) error {
	if len(o.SBOMFormats) == 0 {
		o.Logger().Warnf("skipping SBOM generation")
		return nil
	}

	s := newSBOM(o, ic)

	if err := s.ReadLayerTarball(o.TarballPath); err != nil {
		return fmt.Errorf("reading layer tar: %w", err)
	}

	if err := s.ReadPackageIndex(); err != nil {
		return fmt.Errorf("getting installed packages from sbom: %w", err)
	}

	// Get the image digest
	h, err := img.Digest()
	if err != nil {
		return fmt.Errorf("getting %s image digest: %w", o.Arch, err)
	}

	s.Options.ImageInfo.ImageDigest = h.String()
	s.Options.ImageInfo.Arch = o.Arch

	if _, err := s.Generate(); err != nil {
		return fmt.Errorf("generating SBOMs: %w", err)
	}

	return nil
}

// GenerateSBOM generates an SBOM for an apko layer
func (di *defaultBuildImplementation) GenerateSBOM(o *options.Options, ic *types.ImageConfiguration) error {
	if len(o.SBOMFormats) == 0 {
		o.Logger().Warnf("skipping SBOM generation")
		return nil
	}

	s := newSBOM(o, ic)

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

func (di *defaultBuildImplementation) InitializeApk(o *options.Options, ic *types.ImageConfiguration) error {
	apk, err := chainguardAPK.NewWithOptions(*o)
	if err != nil {
		return err
	}
	return apk.Initialize(ic)
}

func (di *defaultBuildImplementation) AdditionalTags(o *options.Options) error {
	at, err := chainguardAPK.AdditionalTags(*o)
	if err != nil {
		return err
	}
	if at == nil {
		return nil
	}
	o.Tags = append(o.Tags, at...)
	return nil
}

func (di *defaultBuildImplementation) BuildImage(
	o *options.Options, ic *types.ImageConfiguration, e *exec.Executor, s6context *s6.Context,
) ([]tar.Header, error) {
	return buildImage(di, o, ic, s6context)
}

// buildImage is a temporary function to make the fakes work.
// TODO(puerco): In order to have a structure we can mock, we need to split
// image building to its own interface or split out to its own package.
func buildImage(
	di buildImplementation, o *options.Options, ic *types.ImageConfiguration,
	s6context *s6.Context,
) ([]tar.Header, error) {
	o.Logger().Infof("doing pre-flight checks")
	if err := di.ValidateImageConfiguration(ic); err != nil {
		return nil, fmt.Errorf("failed to validate configuration: %w", err)
	}

	o.Logger().Infof("building image fileystem in %s", o.WorkDir)

	if err := di.InitializeApk(o, ic); err != nil {
		return nil, fmt.Errorf("initializing apk: %w", err)
	}

	if err := di.AdditionalTags(o); err != nil {
		return nil, fmt.Errorf("adding additional tags: %w", err)
	}

	if err := di.MutateAccounts(o, ic); err != nil {
		return nil, fmt.Errorf("failed to mutate accounts: %w", err)
	}

	headers, err := di.MutatePaths(o, ic)
	if err != nil {
		return nil, fmt.Errorf("failed to mutate paths: %w", err)
	}

	if err := di.GenerateOSRelease(o, ic); err != nil {
		if errors.Is(err, ErrOSReleaseAlreadyPresent) {
			o.Logger().Warnf("did not generate /etc/os-release: %v", err)
		} else {
			return nil, fmt.Errorf("failed to generate /etc/os-release: %w", err)
		}
	}

	if err := di.WriteSupervisionTree(s6context, ic); err != nil {
		return nil, fmt.Errorf("failed to write supervision tree: %w", err)
	}

	o.Logger().Infof("finished building filesystem in %s", o.WorkDir)

	return headers, nil
}

func newSBOM(o *options.Options, ic *types.ImageConfiguration) *sbom.SBOM {
	s := sbom.NewWithWorkDir(o.WorkDir, o.Arch)
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

func (di *defaultBuildImplementation) GenerateIndexSBOM(
	o *options.Options, ic *types.ImageConfiguration,
	indexDigest name.Digest, imgs map[types.Architecture]coci.SignedImage,
) error {
	if len(o.SBOMFormats) == 0 {
		o.Logger().Warnf("skipping index SBOM generation")
		return nil
	}

	s := newSBOM(o, ic)
	o.Logger().Infof("Generating index SBOM")

	// Add the image digest
	h, err := v1.NewHash(indexDigest.DigestStr())
	if err != nil {
		return errors.New("getting index hash")
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
		sbomHash, err := hash.SHA256ForFile(filepath.Join(s.Options.OutputDir, fmt.Sprintf("sbom-%s.%s", arch.ToAPK(), ext)))
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

func installBusyboxLinks(root fs.FS) (fs.FS, error) {
	memfsImpl := memfs.New()
	// does busybox exist? if not, do not bother with symlinks
	f, err := root.Open("/bin/busybox")
	if err != nil {
		return memfsImpl, err
	}
	f.Close()
	for _, link := range busyboxLinks {
		dir := filepath.Dir(link)
		if err := memfsImpl.MkdirAll(dir, 0755); err != nil {
			return memfsImpl, fmt.Errorf("creating directory %s: %w", dir, err)
		}
		if err := memfsImpl.Symlink("/bin/busybox", link); err != nil {
			return memfsImpl, fmt.Errorf("creating busybox link %s: %w", link, err)
		}
	}
	return memfsImpl, nil
}

func installLdconfigLinks(root apkofs.OpenReaderAtFS) (fs.FS, error) {
	memfsImpl := memfs.New()
	linksMap, err := ldconfig(root, "/lib")
	if err != nil {
		return memfsImpl, err
	}
	for link, target := range linksMap {
		dir := filepath.Dir(link)
		if err := memfsImpl.MkdirAll(dir, 0755); err != nil {
			return memfsImpl, fmt.Errorf("creating directory %s: %w", dir, err)
		}
		if err := memfsImpl.Symlink(target, link); err != nil {
			return memfsImpl, fmt.Errorf("creating link %s -> %s: %w", link, target, err)
		}
	}
	return memfsImpl, nil
}

func mergeFS(srcs ...fs.FS) (fs.FS, error) {
	memfsImpl := memfs.New()
	for _, fsys := range srcs {
		if err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
			// skip the root path, superfluous
			if path == "." {
				return nil
			}

			if err != nil {
				return err
			}

			info, err := d.Info()
			if err != nil {
				return err
			}
			mode := info.Mode()

			switch {
			case mode&os.ModeSymlink == os.ModeSymlink:
				rlfs, ok := fsys.(apkofs.ReadLinkFS)
				if !ok {
					return fmt.Errorf("readlink not supported by this fs: path (%s)", path)
				}

				link, symlink, err := rlfs.Readlink(path)
				if err != nil {
					return err
				}
				if symlink {
					err = memfsImpl.Symlink(link, path)
				} else {
					err = memfsImpl.Link(link, path)
				}
				return err
			case mode&os.ModeCharDevice == os.ModeCharDevice:
				readnodfs, ok := fsys.(apkofs.ReadnodFS)
				if !ok {
					return fmt.Errorf("read character device not supported by this fs: path (%s) %#v %#v", path, info, fsys)
				}
				dev, err := readnodfs.Readnod(path)
				if err != nil {
					return err
				}
				perms := uint32(mode.Perm())
				if err := memfsImpl.Mknod(path, unix.S_IFCHR|perms, dev); err != nil {
					return err
				}

			case mode.IsDir():
				if err := memfsImpl.MkdirAll(path, mode); err != nil {
					return err
				}
			case mode.IsRegular():
				in, err := fsys.Open(path)
				if err != nil {
					return err
				}
				defer in.Close()
				// if the file already exists, override it
				if _, err := memfsImpl.Stat(path); err == nil {
					if err := memfsImpl.Remove(path); err != nil {
						return err
					}
				}
				out, err := memfsImpl.OpenFile(path, os.O_CREATE|os.O_WRONLY, mode)
				if err != nil {
					return err
				}
				defer out.Close()

				if _, err := io.Copy(out, in); err != nil {
					return err
				}
			}

			return nil
		}); err != nil {
			return nil, err
		}
	}
	return memfsImpl, nil
}
func installCharDevices(root apkofs.OpenReaderAtFS) (fs.FS, error) {
	memfsImpl := memfs.New()
	devices := []struct {
		path  string
		major uint32
		minor uint32
	}{
		{"/dev/zero", 1, 5},
		{"/dev/urandom", 1, 9},
		{"/dev/null", 1, 3},
		{"/dev/random", 1, 8},
		{"/dev/console", 5, 1},
	}
	for _, dev := range devices {
		f, err := root.Open(dev.path)
		if err == nil {
			f.Close()
			continue
		}
		dir := filepath.Dir(dev.path)
		if err := memfsImpl.MkdirAll(dir, 0755); err != nil {
			return memfsImpl, fmt.Errorf("creating directory %s: %w", dir, err)
		}
		if err := memfsImpl.Mknod(dev.path, unix.S_IFCHR, int(unix.Mkdev(dev.major, dev.minor))); err != nil {
			return memfsImpl, fmt.Errorf("creating character device %s: %w", dev.path, err)
		}
	}
	return memfsImpl, nil
}
