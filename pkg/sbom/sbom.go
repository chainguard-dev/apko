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

import (
	"fmt"
	"os"
	"path/filepath"

	osr "github.com/dominodatalab/os-release"
	"gitlab.alpinelinux.org/alpine/go/pkg/repository"
)

const (
	osReleasePath    = "/etc/os-release"
	packageIndexPath = "/lib/apk/db/installed"
)

type Options struct {
	OsName    string
	OsID      string
	OsVersion string

	// Working directory,inherited from buid context
	WorkDir string
}

var DefaultOptions = Options{
	OsName:    "Alpine Linux",
	OsID:      "alpine",
	OsVersion: "Unknown",
}

type SBOM struct {
	impl    sbomImplementation
	Options Options
}

func New() *SBOM {
	return &SBOM{
		impl:    &defaultSBOMImplementation{},
		Options: DefaultOptions,
	}
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

type sbomImplementation interface {
	readReleaseData(*Options, string) error
	readPackageIndex(*Options, string) ([]*repository.Package, error)
}

type defaultSBOMImplementation struct{}

// readReleaseDataInternal reads the information from /etc/os-release
func (di *defaultSBOMImplementation) readReleaseData(opts *Options, path string) error {
	osReleaseData, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading os-release: %w", err)
	}

	info := osr.Parse(string(osReleaseData))
	fmt.Printf("%+v", info)

	opts.OsName = info.Name
	opts.OsID = info.ID
	opts.OsVersion = info.VersionID
	return nil
}

// readPackageIndex parses the apk database passed in the path
func (di *defaultSBOMImplementation) readPackageIndex(
	opts *Options, path string,
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
