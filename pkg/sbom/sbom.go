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

package sbom

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

import (
	"fmt"
	"io"
	"io/fs"
	"path/filepath"

	osr "github.com/dominodatalab/os-release"
	v1tar "github.com/google/go-containerregistry/pkg/v1/tarball"
	"gitlab.alpinelinux.org/alpine/go/pkg/repository"

	apkfs "chainguard.dev/apko/pkg/apk/impl/fs"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/sbom/generator"
	"chainguard.dev/apko/pkg/sbom/options"
)

var (
	osReleasePath    = filepath.Join("etc", "os-release")
	packageIndexPath = filepath.Join("lib", "apk", "db", "installed")
)

var DefaultOptions = options.Options{
	OS: options.OSInfo{
		ID:      "unknown",
		Name:    "Alpine Linux",
		Version: "Unknown",
	},
	ImageInfo: options.ImageInfo{
		Images: []options.ArchImageInfo{},
	},
	FileName: "sbom",
	Formats:  []string{"spdx", "cyclonedx"},
}

type SBOM struct {
	Generators map[string]generator.Generator
	impl       sbomImplementation
	Options    options.Options
}

func New(fs apkfs.FullFS) *SBOM {
	return &SBOM{
		Generators: generator.Generators(fs),
		impl:       &defaultSBOMImplementation{},
		Options:    DefaultOptions,
	}
}

// NewWithWorkDir returns a new sbom object with a working dir preset
func NewWithFS(fs apkfs.FullFS, a types.Architecture) *SBOM {
	s := New(fs)
	s.Options.FS = fs
	s.Options.FileName = fmt.Sprintf("sbom-%s", a.ToAPK())
	return s
}

func (s *SBOM) SetImplementation(impl sbomImplementation) {
	s.impl = impl
}

func (s *SBOM) ReadReleaseData() error {
	if err := s.impl.ReadReleaseData(
		s.Options.FS, &s.Options, osReleasePath,
	); err != nil {
		return fmt.Errorf("reading release data: %w", err)
	}
	return nil
}

// ReadPackageIndex parses the package index in the working directory
// and returns a slice of the installed packages
func (s *SBOM) ReadPackageIndex() error {
	pks, err := s.impl.ReadPackageIndex(
		s.Options.FS, &s.Options, packageIndexPath,
	)
	if err != nil {
		return fmt.Errorf("reading apk package index: %w", err)
	}
	s.Options.Packages = pks
	return nil
}

// Generate creates the sboms according to the options set
func (s *SBOM) Generate() ([]string, error) {
	// s.Options.Logger().Infof("generating SBOM")
	if err := s.impl.CheckGenerators(
		&s.Options, s.Generators,
	); err != nil {
		return nil, err
	}
	files, err := s.impl.Generate(&s.Options, s.Generators)
	if err != nil {
		return nil, fmt.Errorf("generating sboms: %w", err)
	}
	return files, nil
}

// Generate creates the sboms according to the options set
func (s *SBOM) GenerateIndex() ([]string, error) {
	if err := s.impl.CheckGenerators(
		&s.Options, s.Generators,
	); err != nil {
		return nil, err
	}
	files, err := s.impl.GenerateIndex(&s.Options, s.Generators)
	if err != nil {
		return nil, fmt.Errorf("generating sboms: %w", err)
	}
	return files, nil
}

// ReadLayerTarball reads an apko layer tarball and adds its metadata to the SBOM options
func (s *SBOM) ReadLayerTarball(path string) error {
	return s.impl.ReadLayerTarball(&s.Options, path)
}

//counterfeiter:generate . sbomImplementation
type sbomImplementation interface {
	ReadReleaseData(fs.FS, *options.Options, string) error
	ReadPackageIndex(fs.FS, *options.Options, string) ([]*repository.Package, error)
	Generate(*options.Options, map[string]generator.Generator) ([]string, error)
	CheckGenerators(*options.Options, map[string]generator.Generator) error
	GenerateIndex(*options.Options, map[string]generator.Generator) ([]string, error)
	ReadLayerTarball(*options.Options, string) error
}

type defaultSBOMImplementation struct{}

// readReleaseDataInternal reads the information from /etc/os-release
func (di *defaultSBOMImplementation) ReadReleaseData(fsys fs.FS, opts *options.Options, path string) error {
	f, err := fsys.Open(path)
	if err != nil {
		return fmt.Errorf("opening os-release: %w", err)
	}
	defer f.Close()
	osReleaseData, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("reading os-release: %w", err)
	}

	info := osr.Parse(string(osReleaseData))

	opts.OS.Name = info.Name
	opts.OS.ID = info.ID
	opts.OS.Version = info.VersionID
	return nil
}

// readPackageIndex parses the apk database passed in the path
func (di *defaultSBOMImplementation) ReadPackageIndex(
	fsys fs.FS, opts *options.Options, path string,
) (packages []*repository.Package, err error) {
	return ReadPackageIndex(fsys, opts, path)
}

func ReadPackageIndex(fsys fs.FS, opts *options.Options, path string) (packages []*repository.Package, err error) {
	installedDB, err := fsys.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening APK installed db: %w", err)
	}
	defer installedDB.Close()

	// repository.ParsePackageIndex closes the file itself
	packages, err = repository.ParsePackageIndex(installedDB)
	if err != nil {
		return nil, fmt.Errorf("parsing APK installed db: %w", err)
	}
	return packages, nil
}

// generate creates the documents according to the specified options
func (di *defaultSBOMImplementation) Generate(
	opts *options.Options, generators map[string]generator.Generator,
) ([]string, error) {
	files := []string{}
	for _, format := range opts.Formats {
		path := filepath.Join(
			opts.OutputDir, opts.FileName+"."+generators[format].Ext(),
		)
		if err := generators[format].Generate(opts, path); err != nil {
			return nil, fmt.Errorf("generating %s sbom: %w", format, err)
		}
		files = append(files, path)
	}
	return files, nil
}

// checkGenerators verifies we have generators available for the
// formats specified in the options
func (di *defaultSBOMImplementation) CheckGenerators(
	opts *options.Options, generators map[string]generator.Generator,
) error {
	if len(generators) == 0 {
		return fmt.Errorf("no generators defined")
	}
	if len(opts.Formats) == 0 {
		return fmt.Errorf("no sbom format enabled in options")
	}
	for _, format := range opts.Formats {
		if _, ok := generators[format]; !ok {
			return fmt.Errorf(
				"unable to generate sboms: no generator available for format %s", format,
			)
		}
	}
	return nil
}

// GenerateIndex generates the index SBOM for a multi-arch image
func (di *defaultSBOMImplementation) GenerateIndex(opts *options.Options, generators map[string]generator.Generator) ([]string, error) {
	sboms := []string{}
	for _, format := range opts.Formats {
		path := filepath.Join(
			opts.OutputDir, "sbom-index."+generators[format].Ext(),
		)
		if err := generators[format].GenerateIndex(opts, path); err != nil {
			return nil, fmt.Errorf("generating %s sbom: %w", format, err)
		}
		sboms = append(sboms, path)
	}
	return sboms, nil
}

// ReadLayerTarball reads an apko layer adding its digest to the sbom options
func (di *defaultSBOMImplementation) ReadLayerTarball(opts *options.Options, tarballPath string) error {
	v1Layer, err := v1tar.LayerFromFile(tarballPath)
	if err != nil {
		return fmt.Errorf("failed to create OCI layer from tar.gz: %w", err)
	}

	digest, err := v1Layer.Digest()
	if err != nil {
		return fmt.Errorf("could not calculate layer digest: %w", err)
	}
	opts.ImageInfo.LayerDigest = digest.String()
	return nil
}
