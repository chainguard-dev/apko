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

package spdx

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"

	"sigs.k8s.io/release-utils/version"

	"chainguard.dev/apko/pkg/sbom/options"
	purl "github.com/package-url/packageurl-go"
)

// https://spdx.github.io/spdx-spec/3-package-information/#32-package-spdx-identifier
var validIDCharsRe = regexp.MustCompile(`[^a-zA-Z0-9-.]+`)

const NOASSERTION = "NOASSERTION"

type SPDX struct{}

func New() SPDX {
	return SPDX{}
}

func (sx *SPDX) Key() string {
	return "spdx"
}

func (sx *SPDX) Ext() string {
	return "spdx.json"
}

func stringToIdentifier(in string) (out string) {
	return validIDCharsRe.ReplaceAllStringFunc(in, func(s string) string {
		r := ""
		for i := 0; i < len(s); i++ {
			uc, _ := utf8.DecodeRuneInString(string(s[i]))
			r = fmt.Sprintf("%sC%d", r, uc)
		}
		return r
	})
}

// Generate writes a cyclondx sbom in path
func (sx *SPDX) Generate(opts *options.Options, path string) error {
	// The default document name makes no attempt to avoid
	// clashes. Ensuring a unique name requires a digest
	documentName := "sbom"
	if opts.ImageInfo.Digest != "" {
		documentName += "-" + opts.ImageInfo.Digest
	}
	doc := &Document{
		ID:      "SPDXRef-DOCUMENT",
		Name:    documentName,
		Version: "SPDX-2.2",
		CreationInfo: CreationInfo{
			Created: "1970-01-01T00:00:00Z",
			Creators: []string{
				fmt.Sprintf("Tool: apko (%s)", version.GetVersionInfo().GitVersion),
				"Organization: Chainguard, Inc",
			},
			LicenseListVersion: "3.16",
		},
		DataLicense:   "CC0-1.0",
		Namespace:     "https://spdx.org/spdxdocs/apko/",
		Packages:      []Package{},
		Relationships: []Relationship{},
	}

	mainPkgName := "apko-os-layer"
	if opts.ImageInfo.Reference != "" {
		x := ""
		if !strings.Contains(opts.ImageInfo.Reference, "/") {
			x = "index.docker.io/library/"
		}
		mainPkgName = fmt.Sprintf("SPDXRef-%s%s", x, opts.ImageInfo.Reference)
	}
	mainPkgID := stringToIdentifier(mainPkgName)

	// Main package purl
	mmMain := map[string]string{}
	if opts.ImageInfo.Tag != "" {
		mmMain["tag"] = opts.ImageInfo.Tag
	}
	if opts.ImageInfo.Repository != "" {
		mmMain["repository_url"] = opts.ImageInfo.Repository
	}
	if opts.ImageInfo.Arch != "" {
		mmMain["arch"] = opts.ImageInfo.Arch.ToOCIPlatform().Architecture
	}

	mainPackage := Package{
		ID:               fmt.Sprintf("SPDXRef-Package-%s", mainPkgID),
		Name:             mainPkgName,
		Version:          opts.OS.Version,
		FilesAnalyzed:    false,
		LicenseConcluded: NOASSERTION,
		LicenseDeclared:  NOASSERTION,
		Description:      "",
		DownloadLocation: NOASSERTION,
		Originator:       "",
		SourceInfo:       "",
		CopyrightText:    NOASSERTION,
		Checksums:        []Checksum{},
		ExternalRefs: []ExternalRef{
			{
				Category: "PACKAGE_MANAGER",
				Type:     "purl",
				Locator: purl.NewPackageURL(
					purl.TypeOCI, "", opts.ImageInfo.Name, opts.ImageInfo.Digest,
					purl.QualifiersFromMap(mmMain), "",
				).String(),
			},
		},
	}
	mm := map[string]string{"arch": opts.ImageInfo.Arch.ToAPK()}

	doc.Packages = append(doc.Packages, mainPackage)
	doc.DocumentDescribes = []string{mainPackage.ID}

	for _, pkg := range opts.Packages {
		// add the package
		p := Package{
			ID: stringToIdentifier(fmt.Sprintf(
				"SPDXRef-Package-%s-%s-%s", mainPkgID, pkg.Name, pkg.Version,
			)),
			Name:             pkg.Name,
			Version:          pkg.Version,
			FilesAnalyzed:    false,
			LicenseConcluded: pkg.License,
			LicenseDeclared:  NOASSERTION,
			Description:      pkg.Description,
			DownloadLocation: pkg.URL,
			Originator:       pkg.Maintainer,
			SourceInfo:       "Package info from apk database",
			CopyrightText:    NOASSERTION,
			Checksums: []Checksum{
				{
					Algorithm: "SHA1",
					Value:     fmt.Sprintf("%x", pkg.Checksum),
				},
			},
			ExternalRefs: []ExternalRef{
				{
					Category: "PACKAGE_MANAGER",
					Locator: purl.NewPackageURL(
						"apk", opts.OS.ID, pkg.Name, pkg.Version,
						purl.QualifiersFromMap(mm), "").String(),
					Type: "purl",
				},
			},
		}

		doc.Packages = append(doc.Packages, p)

		// Add to the relationships list
		doc.Relationships = append(doc.Relationships, Relationship{
			Element: mainPackage.ID,
			Type:    "CONTAINS",
			Related: p.ID,
		})
	}

	out, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("opening SBOM path %s for writing: %w", path, err)
	}
	defer out.Close()

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")

	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encoding spdx sbom: %w", err)
	}

	return nil
}

type Document struct {
	ID                string         `json:"SPDXID"`
	Name              string         `json:"name"`
	Version           string         `json:"spdxVersion"`
	CreationInfo      CreationInfo   `json:"creationInfo"`
	DataLicense       string         `json:"dataLicense"`
	Namespace         string         `json:"documentNamespace"`
	DocumentDescribes []string       `json:"documentDescribes"`
	Packages          []Package      `json:"packages"`
	Relationships     []Relationship `json:"relationships"`
}

type CreationInfo struct {
	Created            string   `json:"created"` // Date
	Creators           []string `json:"creators"`
	LicenseListVersion string   `json:"licenseListVersion"`
}

type Package struct {
	ID               string        `json:"SPDXID"`
	Name             string        `json:"name"`
	Version          string        `json:"versionInfo"`
	FilesAnalyzed    bool          `json:"filesAnalyzed"`
	LicenseConcluded string        `json:"licenseConcluded"`
	LicenseDeclared  string        `json:"licenseDeclared"`
	Description      string        `json:"description"`
	DownloadLocation string        `json:"downloadLocation"`
	Originator       string        `json:"originator"`
	SourceInfo       string        `json:"sourceInfo"`
	CopyrightText    string        `json:"copyrightText"`
	Checksums        []Checksum    `json:"checksums"`
	ExternalRefs     []ExternalRef `json:"externalRefs"`
}

type Checksum struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"checksumValue"`
}

type ExternalRef struct {
	Category string `json:"referenceCategory"`
	Locator  string `json:"referenceLocator"`
	Type     string `json:"referenceType"`
}

type Relationship struct {
	Element string `json:"spdxElementId"`
	Type    string `json:"relationshipType"`
	Related string `json:"relatedSpdxElement"`
}
