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

package spdx

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/chainguard-dev/go-apk/pkg/apk"
	apkfs "github.com/chainguard-dev/go-apk/pkg/fs"
	purl "github.com/package-url/packageurl-go"
	"sigs.k8s.io/release-utils/version"

	"chainguard.dev/apko/pkg/sbom/options"
)

// https://spdx.github.io/spdx-spec/3-package-information/#32-package-spdx-identifier
var validIDCharsRe = regexp.MustCompile(`[^a-zA-Z0-9-.]+`)

const (
	NOASSERTION          = "NOASSERTION"
	ExtRefPackageManager = "PACKAGE-MANAGER"
	ExtRefTypePurl       = "purl"
	apkSBOMdir           = "/var/lib/db/sbom"
)

type SPDX struct {
	fs apkfs.FullFS
}

func New(fs apkfs.FullFS) SPDX {
	return SPDX{fs}
}

func (sx *SPDX) Key() string {
	return "spdx"
}

func (sx *SPDX) Ext() string {
	return "spdx.json"
}

func stringToIdentifier(in string) (out string) {
	in = strings.ReplaceAll(in, ":", "-")
	return validIDCharsRe.ReplaceAllStringFunc(in, func(s string) string {
		r := ""
		for i := 0; i < len(s); i++ {
			uc, _ := utf8.DecodeRuneInString(string(s[i]))
			r = fmt.Sprintf("%sC%d", r, uc)
		}
		return r
	})
}

// Generate writes an SPDX SBOM in path
func (sx *SPDX) Generate(opts *options.Options, path string) error {
	// The default document name makes no attempt to avoid
	// clashes. Ensuring a unique name requires a digest
	documentName := "sbom"
	if opts.ImageInfo.LayerDigest != "" {
		documentName += "-" + opts.ImageInfo.LayerDigest
	}
	doc := &Document{
		ID:      "SPDXRef-DOCUMENT",
		Name:    documentName,
		Version: "SPDX-2.3",
		CreationInfo: CreationInfo{
			Created: opts.ImageInfo.SourceDateEpoch.Format(time.RFC3339),
			Creators: []string{
				fmt.Sprintf("Tool: apko (%s)", version.GetVersionInfo().GitVersion),
				"Organization: Chainguard, Inc",
			},
			LicenseListVersion: "3.16",
		},
		DataLicense:   "CC0-1.0",
		Namespace:     "https://spdx.org/spdxdocs/apko/",
		Packages:      []Package{},
		Files:         []File{},
		Relationships: []Relationship{},
	}
	var imagePackage *Package
	layerPackage := sx.layerPackage(opts)

	doc.DocumentDescribes = []string{layerPackage.ID}

	if opts.ImageInfo.ImageDigest != "" {
		imagePackage = sx.imagePackage(opts)
		doc.DocumentDescribes = []string{imagePackage.ID}
		doc.Packages = append(doc.Packages, *imagePackage)
		// Add to the relationships list
		doc.Relationships = append(doc.Relationships, Relationship{
			Element: imagePackage.ID,
			Type:    "CONTAINS",
			Related: layerPackage.ID,
		})
	}

	if opts.ImageInfo.VCSUrl != "" {
		if opts.ImageInfo.ImageDigest != "" {
			addSourcePackage(opts.ImageInfo.VCSUrl, doc, imagePackage, opts)
		}
	}

	doc.Packages = append(doc.Packages, *layerPackage)

	for _, pkg := range opts.Packages {
		// add the package
		p := sx.apkPackage(opts, pkg)
		// Add the layer to the ID to avoid clashes
		p.ID = stringToIdentifier(fmt.Sprintf(
			"SPDXRef-Package-%s-%s-%s", layerPackage.ID, pkg.Name, pkg.Version,
		))

		doc.Packages = append(doc.Packages, p)

		// Add to the relationships list
		doc.Relationships = append(doc.Relationships, Relationship{
			Element: layerPackage.ID,
			Type:    "CONTAINS",
			Related: p.ID,
		})

		// Check to see if the apk contains an sbom describing itself
		if err := sx.ProcessInternalApkSBOM(opts, doc, &p); err != nil {
			return fmt.Errorf("parsing internal apk SBOM: %w", err)
		}
	}

	if err := renderDoc(doc, path); err != nil {
		return fmt.Errorf("rendering document: %w", err)
	}

	return nil
}

// replacePackage replaces a package with ID originalID with newID
func replacePackage(doc *Document, originalID, newID string) {
	// First check if package is described at the top of the SBOM
	for i := range doc.DocumentDescribes {
		if doc.DocumentDescribes[i] == originalID {
			doc.DocumentDescribes[i] = newID
			break
		}
	}

	// Now, look at all relationships and replace
	for i := range doc.Relationships {
		if doc.Relationships[i].Element == originalID {
			doc.Relationships[i].Element = newID
		}
		if doc.Relationships[i].Related == originalID {
			doc.Relationships[i].Related = newID
		}
	}

	// Remove the old ID from the package list
	newPackages := []Package{}
	replaced := false
	for _, r := range doc.Packages {
		if r.ID != originalID {
			newPackages = append(newPackages, r)
			replaced = true
		}
	}
	if replaced {
		doc.Packages = newPackages
	}
}

// locateApkSBOM returns the SBOM
func locateApkSBOM(fsys apkfs.FullFS, p *Package) (string, error) {
	re := regexp.MustCompile(`-r\d+$`)
	for _, s := range []string{
		fmt.Sprintf("%s/%s-%s.spdx.json", apkSBOMdir, p.Name, p.Version),
		fmt.Sprintf("%s/%s-%s.spdx.json", apkSBOMdir, p.Name, re.ReplaceAllString(p.Version, "")),
		fmt.Sprintf("%s/%s.spdx.json", apkSBOMdir, p.Name),
	} {
		info, err := fsys.Stat(s)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
		}

		if info.IsDir() {
			return "", fmt.Errorf("directory found at SBOM path %s", s)
		}
		return s, nil
	}

	return "", nil
}

func (sx *SPDX) ProcessInternalApkSBOM(opts *options.Options, doc *Document, p *Package) error {
	// Check if apk installed an SBOM
	path, err := locateApkSBOM(sx.fs, p)
	if err != nil {
		return fmt.Errorf("inspecting FS for internal apk SBOM: %w", err)
	}
	if path == "" {
		return nil
	}

	internalDoc, err := sx.ParseInternalSBOM(opts, path)
	if err != nil {
		// TODO: Log error parsing apk SBOM
		return nil
	}

	// Cycle the top level elements...
	elementIDs := map[string]struct{}{}
	for _, elementID := range internalDoc.DocumentDescribes {
		elementIDs[elementID] = struct{}{}
	}

	// ... searching for a 1st level package
	targetElementIDs := map[string]struct{}{}
	for _, pkg := range internalDoc.Packages {
		// that matches the name
		if p.Name != pkg.Name {
			continue
		}

		if _, ok := elementIDs[pkg.ID]; !ok {
			continue
		}

		targetElementIDs[pkg.ID] = struct{}{}
		if len(targetElementIDs) == len(elementIDs) {
			// Exit early if we found them all.
			break
		}
	}

	// Copy the targetElementIDs
	todo := make(map[string]struct{}, len(internalDoc.Relationships))
	for id := range targetElementIDs {
		todo[id] = struct{}{}
	}

	if err := copySBOMElements(internalDoc, doc, todo); err != nil {
		return fmt.Errorf("copying element: %w", err)
	}

	// TODO: This loop seems very wrong.
	for id := range targetElementIDs {
		// Search for a package in the new SBOM describing the same thing
		for _, pkg := range doc.Packages {
			// TODO: Think if we need to match version too
			if pkg.Name == p.Name {
				replacePackage(doc, pkg.ID, id)
				break
			}
		}
	}

	return nil
}

func copySBOMElements(sourceDoc, targetDoc *Document, todo map[string]struct{}) error {
	// Walk the graph looking for things to copy.
	// Loop until we don't find any new todos.
	for prev, next := 0, len(todo); next != prev; prev, next = next, len(todo) {
		for _, r := range sourceDoc.Relationships {
			if _, ok := todo[r.Element]; ok {
				todo[r.Related] = struct{}{}
			}
		}
	}

	// Now copy everything over.
	done := make(map[string]struct{}, len(todo))

	for _, p := range sourceDoc.Packages {
		if _, ok := todo[p.ID]; ok {
			targetDoc.Packages = append(targetDoc.Packages, p)
			done[p.ID] = struct{}{}
		}
	}

	for _, f := range sourceDoc.Files {
		if _, ok := todo[f.ID]; ok {
			f.Name = strings.TrimPrefix(f.Name, "/") // Strip leading slashes, which SPDX doesn't like.

			targetDoc.Files = append(targetDoc.Files, f)
			done[f.ID] = struct{}{}
		}
	}

	for _, r := range sourceDoc.Relationships {
		if _, ok := todo[r.Element]; ok {
			targetDoc.Relationships = append(targetDoc.Relationships, r)
		}
	}

	if missed := len(todo) - len(done); missed != 0 {
		missing := make([]string, 0, missed)

		for want := range todo {
			if _, ok := done[want]; !ok {
				missing = append(missing, want)
			}
		}

		return fmt.Errorf("unable to find %d elements in source document: %v", missed, missing)
	}

	return nil
}

// ParseInternalSBOM opens an SBOM inside apks and
func (sx *SPDX) ParseInternalSBOM(opts *options.Options, path string) (*Document, error) {
	internalSBOM := &Document{}
	data, err := sx.fs.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("opening sbom file %s: %w", path, err)
	}

	if err := json.Unmarshal(data, internalSBOM); err != nil {
		return nil, fmt.Errorf("parsing internal apk sbom: %w", err)
	}
	return internalSBOM, nil
}

// renderDoc marshals a document to json and writes it to disk
func renderDoc(doc *Document, path string) error {
	out, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("opening SBOM path %s for writing: %w", path, err)
	}
	defer out.Close()

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(true)

	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encoding spdx sbom: %w", err)
	}
	return nil
}

func (sx *SPDX) imagePackage(opts *options.Options) (p *Package) {
	return &Package{
		ID: stringToIdentifier(fmt.Sprintf(
			"SPDXRef-Package-%s", opts.ImageInfo.ImageDigest,
		)),
		Name:             opts.ImageInfo.ImageDigest,
		Version:          opts.ImageInfo.ImageDigest,
		Supplier:         "Organization: " + opts.OS.Name,
		DownloadLocation: NOASSERTION,
		PrimaryPurpose:   "CONTAINER",
		FilesAnalyzed:    false,
		Description:      "apko container image",
		Checksums: []Checksum{
			{
				Algorithm: "SHA256",
				Value:     strings.TrimPrefix(opts.ImageInfo.ImageDigest, "sha256:"),
			},
		},
		ExternalRefs: []ExternalRef{
			{
				Category: ExtRefPackageManager,
				Type:     ExtRefTypePurl,
				Locator: purl.NewPackageURL(
					purl.TypeOCI, "", opts.ImagePurlName(), opts.ImageInfo.ImageDigest,
					nil, "",
				).String() + "?" + opts.ImagePurlQualifiers().String(),
			},
		},
	}
}

// apkPackage returns a SPDX package describing an apk
func (sx *SPDX) apkPackage(opts *options.Options, pkg *apk.Package) Package {
	return Package{
		ID: stringToIdentifier(fmt.Sprintf(
			"SPDXRef-Package-%s-%s", pkg.Name, pkg.Version,
		)),
		Name:             pkg.Name,
		Version:          pkg.Version,
		Supplier:         "Organization: " + opts.OS.Name,
		FilesAnalyzed:    false,
		LicenseConcluded: pkg.License,
		Description:      pkg.Description,
		DownloadLocation: pkg.URL,
		Originator:       fmt.Sprintf("Person: %s", pkg.Maintainer),
		SourceInfo:       "Package info from apk database",
		Checksums: []Checksum{
			{
				Algorithm: "SHA1",
				Value:     fmt.Sprintf("%x", pkg.Checksum),
			},
		},
		ExternalRefs: []ExternalRef{
			{
				Category: ExtRefPackageManager,
				Locator: purl.NewPackageURL(
					"apk", opts.OS.ID, pkg.Name, pkg.Version,
					purl.QualifiersFromMap(
						map[string]string{"arch": opts.ImageInfo.Arch.ToAPK()},
					), "").String(),
				Type: ExtRefTypePurl,
			},
		},
	}
}

// LayerPackage returns a package describing the layer
func (sx *SPDX) layerPackage(opts *options.Options) *Package {
	layerPackageName := opts.ImageInfo.LayerDigest
	mainPkgID := stringToIdentifier(layerPackageName)

	return &Package{
		ID:               fmt.Sprintf("SPDXRef-Package-%s", mainPkgID),
		Name:             layerPackageName,
		Version:          opts.OS.Version,
		FilesAnalyzed:    false,
		Description:      "apko operating system layer",
		DownloadLocation: NOASSERTION,
		Originator:       "",
		Supplier:         "Organization: " + opts.OS.Name,
		Checksums:        []Checksum{},
		ExternalRefs: []ExternalRef{
			{
				Category: ExtRefPackageManager,
				Type:     ExtRefTypePurl,
				Locator: purl.NewPackageURL(
					purl.TypeOCI, "", opts.ImagePurlName(), opts.ImageInfo.LayerDigest,
					nil, "",
				).String() + "?" + opts.LayerPurlQualifiers().String(),
			},
		},
	}
}

type Document struct {
	ID                   string                `json:"SPDXID"`
	Name                 string                `json:"name"`
	Version              string                `json:"spdxVersion"`
	CreationInfo         CreationInfo          `json:"creationInfo"`
	DataLicense          string                `json:"dataLicense"`
	Namespace            string                `json:"documentNamespace"`
	DocumentDescribes    []string              `json:"documentDescribes"`
	Files                []File                `json:"files,omitempty"`
	Packages             []Package             `json:"packages"`
	Relationships        []Relationship        `json:"relationships"`
	ExternalDocumentRefs []ExternalDocumentRef `json:"externalDocumentRefs,omitempty"`
}

type ExternalDocumentRef struct {
	Checksum           Checksum `json:"checksum"`
	ExternalDocumentID string   `json:"externalDocumentId"`
	SPDXDocument       string   `json:"spdxDocument"`
}

type CreationInfo struct {
	Created            string   `json:"created"` // Date
	Creators           []string `json:"creators"`
	LicenseListVersion string   `json:"licenseListVersion,omitempty"`
	CreatorComment     string   `json:"comment,omitempty"`
}

type File struct {
	ID                string     `json:"SPDXID"`
	Name              string     `json:"fileName"`
	CopyrightText     string     `json:"copyrightText,omitempty"`
	NoticeText        string     `json:"noticeText,omitempty"`
	LicenseConcluded  string     `json:"licenseConcluded,omitempty"`
	Description       string     `json:"description,omitempty"`
	FileTypes         []string   `json:"fileTypes,omitempty"`
	LicenseInfoInFile []string   `json:"licenseInfoInFiles,omitempty"` // List of licenses
	Checksums         []Checksum `json:"checksums,omitempty"`
}

type Package struct {
	ID                   string                   `json:"SPDXID"`
	Name                 string                   `json:"name"`
	Version              string                   `json:"versionInfo,omitempty"`
	FilesAnalyzed        bool                     `json:"filesAnalyzed"`
	HasFiles             []string                 `json:"hasFiles,omitempty"`
	LicenseInfoFromFiles []string                 `json:"licenseInfoFromFiles,omitempty"`
	LicenseConcluded     string                   `json:"licenseConcluded,omitempty"`
	LicenseDeclared      string                   `json:"licenseDeclared,omitempty"`
	Description          string                   `json:"description,omitempty"`
	DownloadLocation     string                   `json:"downloadLocation,omitempty"`
	Originator           string                   `json:"originator,omitempty"`
	Supplier             string                   `json:"supplier,omitempty"`
	SourceInfo           string                   `json:"sourceInfo,omitempty"`
	CopyrightText        string                   `json:"copyrightText,omitempty"`
	PrimaryPurpose       string                   `json:"primaryPackagePurpose,omitempty"`
	Checksums            []Checksum               `json:"checksums,omitempty"`
	ExternalRefs         []ExternalRef            `json:"externalRefs,omitempty"`
	VerificationCode     *PackageVerificationCode `json:"packageVerificationCode,omitempty"`
}

type PackageVerificationCode struct {
	Value         string   `json:"packageVerificationCodeValue,omitempty"`
	ExcludedFiles []string `json:"packageVerificationCodeExcludedFiles,omitempty"`
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

func (sx *SPDX) GenerateIndex(opts *options.Options, path string) error {
	if opts.ImageInfo.Images == nil || len(opts.ImageInfo.Images) == 0 {
		return errors.New("unable to render index sbom, no architecture images found")
	}
	documentName := "sbom"
	if opts.ImageInfo.IndexDigest.DeepCopy().String() != "" {
		documentName = "sbom-" + opts.ImageInfo.IndexDigest.DeepCopy().String()
	}
	doc := &Document{
		ID:      "SPDXRef-DOCUMENT",
		Name:    documentName,
		Version: "SPDX-2.3",
		CreationInfo: CreationInfo{
			Created: opts.ImageInfo.SourceDateEpoch.Format(time.RFC3339),
			Creators: []string{
				fmt.Sprintf("Tool: apko (%s)", version.GetVersionInfo().GitVersion),
				"Organization: Chainguard, Inc",
			},
			LicenseListVersion: "3.16",
			CreatorComment: `This SPDX document describes a multi-architecture container image index, containing one or more architecture-specific images.

The packages described in this document refer to the images contained in the index, and not the contents of the images themselves.

You can find the documents for the individual images in the index, containing the packages present in those images, by consulting the "VARIANT_OF" relationships in this document.

For more info refer to https://github.com/spdx/spdx-examples/blob/master/semantics/oci-multiarch-index.md
`,
		},
		DataLicense:   "CC0-1.0",
		Namespace:     "https://spdx.org/spdxdocs/apko/",
		Packages:      []Package{},
		Relationships: []Relationship{},
	}

	// Create the index package
	indexPackage := Package{
		ID:               "SPDXRef-Package-" + stringToIdentifier(opts.ImageInfo.IndexDigest.DeepCopy().String()),
		Name:             opts.ImageInfo.IndexDigest.DeepCopy().String(),
		Version:          opts.ImageInfo.IndexDigest.DeepCopy().String(),
		Supplier:         "Organization: " + opts.OS.Name,
		FilesAnalyzed:    false,
		Description:      "Multi-arch image index",
		SourceInfo:       "Generated at image build time by apko",
		DownloadLocation: NOASSERTION,
		PrimaryPurpose:   "CONTAINER",
		Checksums: []Checksum{
			{
				Algorithm: "SHA256",
				Value:     opts.ImageInfo.IndexDigest.DeepCopy().Hex,
			},
		},
		ExternalRefs: []ExternalRef{
			{
				Category: ExtRefPackageManager,
				Type:     ExtRefTypePurl,
				Locator: purl.NewPackageURL(
					purl.TypeOCI, "", opts.IndexPurlName(), opts.ImageInfo.IndexDigest.DeepCopy().String(),
					nil, "",
				).String() + "?" + opts.IndexPurlQualifiers().String(),
			},
		},
	}

	doc.Packages = append(doc.Packages, indexPackage)
	doc.DocumentDescribes = append(doc.DocumentDescribes, indexPackage.ID)

	for i, info := range opts.ImageInfo.Images {
		imagePackageID := "SPDXRef-Package-" + stringToIdentifier(info.Digest.DeepCopy().String())

		doc.Packages = append(doc.Packages, Package{
			ID:               imagePackageID,
			Name:             fmt.Sprintf("sha256:%s", info.Digest.DeepCopy().Hex),
			Version:          fmt.Sprintf("sha256:%s", info.Digest.DeepCopy().Hex),
			Supplier:         "Organization: " + opts.OS.Name,
			FilesAnalyzed:    false,
			DownloadLocation: NOASSERTION,
			PrimaryPurpose:   "CONTAINER",
			Checksums: []Checksum{{
				Algorithm: "SHA256",
				Value:     info.Digest.DeepCopy().Hex,
			}},
			ExternalRefs: []ExternalRef{{
				Category: ExtRefPackageManager,
				Type:     ExtRefTypePurl,
				Locator: purl.NewPackageURL(
					purl.TypeOCI, "", opts.ImagePurlName(), info.Digest.DeepCopy().String(),
					nil, "",
				).String() + "?" + opts.ArchImagePurlQualifiers(&opts.ImageInfo.Images[i]).String(),
			}},
		})

		doc.Relationships = append(doc.Relationships, Relationship{
			Element: stringToIdentifier(indexPackage.ID),
			Type:    "VARIANT_OF",
			Related: imagePackageID,
		})
	}

	if opts.ImageInfo.VCSUrl != "" {
		addSourcePackage(opts.ImageInfo.VCSUrl, doc, &indexPackage, opts)
	}

	if err := renderDoc(doc, path); err != nil {
		return fmt.Errorf("rendering document: %w", err)
	}

	return nil
}

// addSourcePackage creates a package describing the source code
func addSourcePackage(vcsURL string, doc *Document, parent *Package, opts *options.Options) {
	version := ""
	checksums := []Checksum{}
	packageName := vcsURL
	if url, commitHash, found := strings.Cut(vcsURL, "@"); found {
		checksums = append(checksums, Checksum{
			Algorithm: "SHA1",
			Value:     commitHash,
		})
		version = commitHash
		packageName = url
	}

	// Trim the schemas from the url for the package name
	packageName = strings.TrimPrefix(packageName, "git+ssh://")
	packageName = strings.TrimPrefix(packageName, "git://")
	packageName = strings.TrimPrefix(packageName, "https://")

	downloadLocation := vcsURL
	if vcsURL == "" {
		downloadLocation = NOASSERTION
	}

	sourcePackage := Package{
		ID:                   fmt.Sprintf("SPDXRef-Package-%s", stringToIdentifier(vcsURL)),
		Name:                 packageName,
		Version:              version,
		Supplier:             "Organization: " + opts.OS.Name,
		FilesAnalyzed:        false,
		HasFiles:             []string{},
		LicenseInfoFromFiles: []string{},
		PrimaryPurpose:       "SOURCE",
		Description:          "Image configuration source",
		DownloadLocation:     downloadLocation,
		Checksums:            checksums,
		ExternalRefs:         []ExternalRef{},
	}

	// If this is a github package, add a purl to it:
	if strings.HasPrefix(packageName, "github.com/") {
		slug := strings.TrimPrefix(packageName, "github.com/")
		org, user, ok := strings.Cut(slug, "/")
		if ok {
			sourcePackage.ExternalRefs = []ExternalRef{
				{
					Category: ExtRefPackageManager,
					Type:     ExtRefTypePurl,
					Locator: purl.NewPackageURL(
						purl.TypeGithub, org, strings.TrimSuffix(user, ".git"), version,
						nil, "",
					).String(),
				},
			}
		}
	}

	doc.Packages = append(doc.Packages, sourcePackage)
	doc.Relationships = append(doc.Relationships, Relationship{
		Element: parent.ID,
		Type:    "GENERATED_FROM",
		Related: sourcePackage.ID,
	})
}
