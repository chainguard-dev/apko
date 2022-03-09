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
)

const (
	osReleasePath = "etc/os-release"
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

func (sbom *SBOM) ReadReleaseData() error {
	if err := sbom.impl.readReleaseData(
		&sbom.Options, filepath.Join(sbom.Options.WorkDir, osReleasePath),
	); err != nil {
		return fmt.Errorf("reading release data: %w", err)
	}
	return nil
}

type sbomImplementation interface {
	readReleaseData(*Options, string) error
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
