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

	"chainguard.dev/apko/pkg/sbom/generator"
	"chainguard.dev/apko/pkg/sbom/options"
	osr "github.com/dominodatalab/os-release"
	"gitlab.alpinelinux.org/alpine/go/pkg/repository"
)

const (
	osReleasePath    = "/etc/os-release"
	packageIndexPath = "/lib/apk/db/installed"
)

var DefaultOptions = options.Options{
	OS: struct {
		Name    string
		ID      string
		Version string
	}{
		ID:      "alpine",
		Name:    "Alpine Linux",
		Version: "Unknown",
	},
	FileName: "sbom",
	Formats:  []string{"cyclonedx"},
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

func (s *SBOM) ReadReleaseData() error {
	if err := s.impl.readReleaseData(
		&s.Options, filepath.Join(s.Options.WorkDir, osReleasePath),
	); err != nil {
		return fmt.Errorf("reading release data: %w", err)
	}
	return nil
}

// ReadPackageIndex parses the package index in the working directory
// and returns a slice of the installed packages
func (s *SBOM) ReadPackageIndex() ([]*repository.Package, error) {
	pks, err := s.impl.readPackageIndex(
		&s.Options, filepath.Join(s.Options.WorkDir, packageIndexPath),
	)
	if err != nil {
		return nil, fmt.Errorf("reading apk package index: %w", err)
	}
	return pks, nil
}

// Generate creates the sboms according to the options set
func (s *SBOM) Generate() ([]string, error) {
	files, err := s.impl.generate(&s.Options, s.Generators)
	if err != nil {
		return nil, fmt.Errorf("generating sboms: %w", err)
	}
	return files, nil
}

//counterfeiter:generate . sbomImplementation
type sbomImplementation interface {
	readReleaseData(*options.Options, string) error
	readPackageIndex(*options.Options, string) ([]*repository.Package, error)
	generate(*options.Options, map[string]generator.Generator) ([]string, error)
}

type defaultSBOMImplementation struct{}

// readReleaseDataInternal reads the information from /etc/os-release
func (di *defaultSBOMImplementation) readReleaseData(opts *options.Options, path string) error {
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
func (di *defaultSBOMImplementation) readPackageIndex(
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
func (di *defaultSBOMImplementation) generate(
	opts *options.Options, generators map[string]generator.Generator,
) ([]string, error) {
	// Check the generators before running
	for _, format := range opts.Formats {
		if _, ok := generators[format]; !ok {
			return nil, fmt.Errorf(
				"unable to generate sboms: no generator available for format %s", format,
			)
		}
	}

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
