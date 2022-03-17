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

package sbom

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

import (
	"fmt"
	"os"
	"path/filepath"

	osr "github.com/dominodatalab/os-release"
	"gitlab.alpinelinux.org/alpine/go/pkg/repository"

	"chainguard.dev/apko/pkg/sbom/generator"
	"chainguard.dev/apko/pkg/sbom/options"
)

var (
	osReleasePath    = filepath.Join("etc", "os-release")
	packageIndexPath = filepath.Join("lib", "apk", "db", "installed")
)

var DefaultOptions = options.Options{
	OS: options.OSInfo{
		ID:      "alpine",
		Name:    "Alpine Linux",
		Version: "Unknown",
	},
	ImageInfo: options.ImageInfo{},
	FileName:  "sbom",
	Formats:   []string{"spdx", "cyclonedx"},
}

type SBOM struct {
	Generators map[string]generator.Generator
	impl       sbomImplementation
	Options    options.Options
}

func New() *SBOM {
	return &SBOM{
		Generators: generator.Generators(),
		impl:       &defaultSBOMImplementation{},
		Options:    DefaultOptions,
	}
}

// NewWithWorkDir returns a new sbom object with a working dir preset
func NewWithWorkDir(path string) *SBOM {
	s := New()
	s.Options.WorkDir = path
	return s
}

func (s *SBOM) SetImplementation(impl sbomImplementation) {
	s.impl = impl
}

func (s *SBOM) ReadReleaseData() error {
	if err := s.impl.ReadReleaseData(
		&s.Options, filepath.Join(s.Options.WorkDir, osReleasePath),
	); err != nil {
		return fmt.Errorf("reading release data: %w", err)
	}
	return nil
}

// ReadPackageIndex parses the package index in the working directory
// and returns a slice of the installed packages
func (s *SBOM) ReadPackageIndex() ([]*repository.Package, error) {
	pks, err := s.impl.ReadPackageIndex(
		&s.Options, filepath.Join(s.Options.WorkDir, packageIndexPath),
	)
	if err != nil {
		return nil, fmt.Errorf("reading apk package index: %w", err)
	}
	return pks, nil
}

// Generate creates the sboms according to the options set
func (s *SBOM) Generate() ([]string, error) {
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

//counterfeiter:generate . sbomImplementation
type sbomImplementation interface {
	ReadReleaseData(*options.Options, string) error
	ReadPackageIndex(*options.Options, string) ([]*repository.Package, error)
	Generate(*options.Options, map[string]generator.Generator) ([]string, error)
	CheckGenerators(*options.Options, map[string]generator.Generator) error
}

type defaultSBOMImplementation struct{}

// readReleaseDataInternal reads the information from /etc/os-release
func (di *defaultSBOMImplementation) ReadReleaseData(opts *options.Options, path string) error {
	osReleaseData, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading os-release: %w", err)
	}

	info := osr.Parse(string(osReleaseData))
	fmt.Printf("%+v", info)

	opts.OS.Name = info.Name
	opts.OS.ID = info.ID
	opts.OS.Version = info.VersionID
	return nil
}

// readPackageIndex parses the apk database passed in the path
func (di *defaultSBOMImplementation) ReadPackageIndex(
	opts *options.Options, path string,
) (packages []*repository.Package, err error) {
	installedDB, err := os.Open(path)
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
