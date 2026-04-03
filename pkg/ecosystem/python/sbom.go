// Copyright 2024 Chainguard, Inc.
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

package python

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/ecosystem"
)

// isChainguardSource returns true if the URL points to a Chainguard Libraries index.
func isChainguardSource(url string) bool {
	return strings.Contains(url, "cgr.dev")
}

// writePackageSBOM writes a minimal SPDX 2.3 SBOM into the dist-info/sboms/ directory.
// This enables `chainctl libraries verify` to confirm Chainguard provenance.
func writePackageSBOM(fsys apkfs.FullFS, sitePackagesPath string, wheelData []byte, pkg ecosystem.ResolvedPackage) error {
	reader, err := zip.NewReader(bytes.NewReader(wheelData), int64(len(wheelData)))
	if err != nil {
		return err
	}

	// Find the .dist-info directory name from the wheel contents.
	var distInfoDir string
	for _, f := range reader.File {
		if strings.HasSuffix(f.Name, ".dist-info/METADATA") {
			distInfoDir = filepath.Dir(f.Name)
			break
		}
	}
	if distInfoDir == "" {
		return fmt.Errorf("no .dist-info/METADATA found in wheel")
	}

	sbomData, err := generatePackageSBOM(pkg)
	if err != nil {
		return fmt.Errorf("generating SBOM: %w", err)
	}

	sbomDir := filepath.Join(sitePackagesPath, distInfoDir, "sboms")
	if err := fsys.MkdirAll(sbomDir, 0755); err != nil {
		return fmt.Errorf("creating sboms directory: %w", err)
	}

	sbomPath := filepath.Join(sbomDir, "sbom.spdx.json")
	return fsys.WriteFile(sbomPath, sbomData, 0644)
}

// spdxDocument is a minimal SPDX 2.3 JSON document structure.
type spdxDocument struct {
	SPDXVersion   string            `json:"spdxVersion"`
	DataLicense   string            `json:"dataLicense"`
	SPDXID        string            `json:"SPDXID"`
	Name          string            `json:"name"`
	Namespace     string            `json:"documentNamespace"`
	CreationInfo  spdxCreationInfo  `json:"creationInfo"`
	Packages      []spdxPackage     `json:"packages"`
}

type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	SPDXID           string `json:"SPDXID"`
	Name             string `json:"name"`
	Version          string `json:"versionInfo"`
	Supplier         string `json:"supplier"`
	Originator       string `json:"originator"`
	DownloadLocation string `json:"downloadLocation"`
	FilesAnalyzed    bool   `json:"filesAnalyzed"`
}

// generatePackageSBOM generates a minimal SPDX 2.3 JSON SBOM for a Chainguard-sourced package.
func generatePackageSBOM(pkg ecosystem.ResolvedPackage) ([]byte, error) {
	doc := spdxDocument{
		SPDXVersion: "SPDX-2.3",
		DataLicense: "CC0-1.0",
		SPDXID:      "SPDXRef-DOCUMENT",
		Name:        pkg.Name + "-" + pkg.Version,
		Namespace:   "https://chainguard.dev/spdx/" + pkg.Name + "-" + pkg.Version,
		CreationInfo: spdxCreationInfo{
			Created:  time.Now().UTC().Format(time.RFC3339),
			Creators: []string{"Tool: apko", "Organization: Chainguard, Inc."},
		},
		Packages: []spdxPackage{{
			SPDXID:           "SPDXRef-Package",
			Name:             pkg.Name,
			Version:          pkg.Version,
			Supplier:         "Organization: Chainguard, Inc.",
			Originator:       "Organization: Chainguard, Inc.",
			DownloadLocation: pkg.URL,
			FilesAnalyzed:    false,
		}},
	}

	return json.MarshalIndent(doc, "", "  ")
}
