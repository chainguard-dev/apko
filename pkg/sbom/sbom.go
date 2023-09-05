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

import (
	"fmt"
	"io"
	"io/fs"
	"path/filepath"

	osr "github.com/dominodatalab/os-release"
	"gitlab.alpinelinux.org/alpine/go/repository"

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

// readReleaseDataInternal reads the information from /etc/os-release
func ReadReleaseData(fsys fs.FS) (*osr.Data, error) {
	f, err := fsys.Open(osReleasePath)
	if err != nil {
		return nil, fmt.Errorf("opening os-release: %w", err)
	}
	defer f.Close()
	osReleaseData, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("reading os-release: %w", err)
	}

	return osr.Parse(string(osReleaseData)), nil
}

func ReadPackageIndex(fsys fs.FS) (packages []*repository.Package, err error) {
	installedDB, err := fsys.Open(packageIndexPath)
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
