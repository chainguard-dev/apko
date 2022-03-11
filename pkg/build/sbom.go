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
	"log"
	"strings"

	"chainguard.dev/apko/pkg/sbom"
)

// GenerateSBOM runs the sbom generation
func (bc *Context) GenerateSBOM() error {
	if len(bc.SBOMFormats) == 0 {
		log.Printf("skipping SBOM generation")
		return nil
	}
	log.Printf("generating SBOM")

	// TODO(puerco): Split GenerateSBOM into context implementation
	s := sbom.NewWithWorkDir(bc.WorkDir)

	// Parse the image reference
	if len(bc.Tags) > 0 {
		parts := strings.Split(bc.Tags[0], ":")
		s.Options.ImageInfo.Reference = parts[0]
		if len(parts) > 1 {
			s.Options.ImageInfo.Tag = parts[1]
		}
		// Split the reference
		parts = strings.Split(s.Options.ImageInfo.Reference, "/")
		s.Options.ImageInfo.Name = parts[len(parts)-1]
		if len(parts) > 1 {
			s.Options.ImageInfo.Repository = strings.Join(parts, "/")
		}
	}

	// Generate the packages externally as we may
	// move the package reader somewhere else
	packages, err := s.ReadPackageIndex()
	if err != nil {
		return fmt.Errorf("getting installed packages from sbom: %w", err)
	}
	s.Options.OutputDir = bc.SBOMPath
	s.Options.Packages = packages
	s.Options.Formats = bc.SBOMFormats

	if _, err := s.Generate(); err != nil {
		return fmt.Errorf("generating SBOMs: %w", err)
	}

	return nil
}
