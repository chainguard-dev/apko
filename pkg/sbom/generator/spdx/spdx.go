// Copyright 2022-2024 Chainguard, Inc.
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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/chainguard-dev/clog"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	purl "github.com/package-url/packageurl-go"
	"sigs.k8s.io/release-utils/version"

	"chainguard.dev/apko/pkg/apk/apk"
	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/sbom/generator"
	"chainguard.dev/apko/pkg/sbom/options"
)

func init() {
	generator.RegisterGenerator("spdx", func() generator.Generator {
		return New()
	})
}

// https://spdx.github.io/spdx-spec/3-package-information/#32-package-spdx-identifier
var validIDCharsRe = regexp.MustCompile(`[^a-zA-Z0-9-.]+`)

const (
	NOASSERTION          = "NOASSERTION"
	ExtRefPackageManager = "PACKAGE-MANAGER"
	ExtRefTypePurl       = "purl"
	apkSBOMdir           = "/var/lib/db/sbom"
)

type SPDX struct{}

func New() *SPDX {
	return &SPDX{}
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

// Returns ":" otherwise :(
func hashToString(h v1.Hash) string {
	if h == (v1.Hash{}) {
		return ""
	}
	return h.String()
}

// Generate writes an SPDX SBOM in path
func (sx *SPDX) Generate(ctx context.Context, opts *options.Options, path string) error {
	// The default document name makes no attempt to avoid
	// clashes. Ensuring a unique name requires a digest
	documentName := "sbom"
	if hash := hashToString(opts.ImageInfo.Layers[0].Digest); hash != "" {
		documentName += "-" + hash
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
		DataLicense:    "CC0-1.0",
		Namespace:      "https://spdx.org/spdxdocs/apko/",
		Packages:       []Package{},
		Relationships:  []Relationship{},
		LicensingInfos: []LicensingInfo{},
	}

	var imagePackage *Package
	if opts.ImageInfo.ImageDigest != "" {
		imagePackage = sx.imagePackage(opts)
		doc.Packages = append(doc.Packages, *imagePackage)
	}

	for _, layer := range opts.ImageInfo.Layers {
		layerPackage := sx.layerPackage(opts, layer)

		// Add to the relationships list
		if imagePackage != nil {
			doc.Relationships = append(doc.Relationships, Relationship{
				Element: imagePackage.ID,
				Type:    "CONTAINS",
				Related: layerPackage.ID,
			})
		} else {
			doc.DocumentDescribes = []string{layerPackage.ID}
		}

		doc.Packages = append(doc.Packages, *layerPackage)
	}

	if imagePackage != nil {
		doc.DocumentDescribes = []string{imagePackage.ID}
	}

	// Add the operating system package
	addOperatingSystem(doc, opts)

	if opts.ImageInfo.VCSUrl != "" {
		if opts.ImageInfo.ImageDigest != "" {
			addSourcePackage(opts.ImageInfo.VCSUrl, doc, imagePackage, opts)
		}
	}

	for _, pkg := range opts.Packages {
		// Check to see if the apk contains an sbom describing itself
		if err := sx.ProcessInternalApkSBOM(ctx, opts, doc, pkg); err != nil {
			return fmt.Errorf("parsing internal apk SBOM: %w", err)
		}
	}

	dedupedPackages := make([]Package, 0, len(doc.Packages))
	seenIDs := make(map[string]struct{})
	for i := range doc.Packages {
		if _, ok := seenIDs[doc.Packages[i].ID]; !ok {
			seenIDs[doc.Packages[i].ID] = struct{}{}
			dedupedPackages = append(dedupedPackages, doc.Packages[i])
		} else {
			clog.FromContext(ctx).Info("duplicate package ID found in SBOM, deduplicating package...", "ID", doc.Packages[i].ID)
		}
	}
	doc.Packages = dedupedPackages

	if err := renderDoc(doc, path); err != nil {
		return fmt.Errorf("rendering document: %w", err)
	}

	return nil
}

// locateApkSBOM returns the path to the SBOM in the given filesystem, using the
// given Package's name and version. It returns an empty string if the SBOM is
// not found.
func locateApkSBOM(fsys apkfs.ReaderFS, ipkg *apk.InstalledPackage) (string, error) {
	re := regexp.MustCompile(`-r\d+$`)
	for _, s := range []string{
		fmt.Sprintf("%s/%s-%s.spdx.json", apkSBOMdir, ipkg.Name, ipkg.Version),
		fmt.Sprintf("%s/%s-%s.spdx.json", apkSBOMdir, ipkg.Name, re.ReplaceAllString(ipkg.Version, "")),
		fmt.Sprintf("%s/%s.spdx.json", apkSBOMdir, ipkg.Name),
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

func (sx *SPDX) ProcessInternalApkSBOM(ctx context.Context, opts *options.Options, doc *Document, ipkg *apk.InstalledPackage) error {
	// Check if apk installed an SBOM
	path, err := locateApkSBOM(opts.FS, ipkg)
	if err != nil {
		return fmt.Errorf("inspecting FS for internal apk SBOM: %w", err)
	}
	if path == "" {
		// The SBOM does not exist.
		// (So just ignore that the package was specified to the SPDX Generate method?)
		return nil
	}

	apkSBOMDoc, err := sx.ParseInternalSBOM(opts, path)
	if err != nil {
		// TODO: Log error parsing apk SBOM
		return nil
	}

	// Cycle the top level elements...
	// Find elements described by the document - check both documentDescribes array
	// and DESCRIBES relationships (from SPDXRef-DOCUMENT)
	idsDescribedByAPKSBOM := map[string]struct{}{}

	// First check documentDescribes array
	for _, elementID := range apkSBOMDoc.DocumentDescribes {
		idsDescribedByAPKSBOM[elementID] = struct{}{}
	}

	// Also check for DESCRIBES relationships from SPDXRef-DOCUMENT
	for _, rel := range apkSBOMDoc.Relationships {
		if rel.Element == "SPDXRef-DOCUMENT" && rel.Type == "DESCRIBES" {
			idsDescribedByAPKSBOM[rel.Related] = struct{}{}
		}
	}

	// ... searching for a 1st level package
	targetElementIDs := map[string]struct{}{}
	for _, pkg := range apkSBOMDoc.Packages {
		if _, ok := idsDescribedByAPKSBOM[pkg.ID]; !ok {
			continue
		}

		targetElementIDs[pkg.ID] = struct{}{}
		if len(targetElementIDs) == len(idsDescribedByAPKSBOM) {
			// Exit early if we found them all.
			break
		}
	}

	// Copy the targetElementIDs
	todo := make(map[string]struct{}, len(apkSBOMDoc.Relationships))
	for id := range targetElementIDs {
		todo[id] = struct{}{}
	}

	if err := copySBOMElements(apkSBOMDoc, doc, todo); err != nil {
		return fmt.Errorf("copying element: %w", err)
	}

	mergeLicensingInfos(ctx, apkSBOMDoc, doc)

	// Add CONTAINS relationships from the document root package to all top-level elements from the internal SBOM.
	// This ensures they are reachable from the document root for tools that traverse the SBOM graph.
	if len(doc.DocumentDescribes) > 0 {
		rootPkgID := doc.DocumentDescribes[0]
		for elementID := range targetElementIDs {
			doc.Relationships = append(doc.Relationships, Relationship{
				Element: rootPkgID,
				Type:    "CONTAINS",
				Related: elementID,
			})
		}
	}

	return nil
}

func copySBOMElements(sourceDoc, targetDoc *Document, todo map[string]struct{}) error {
	// Walk the graph looking for things to copy.
	// Loop until we don't find any new todos.
	for prev, next := 0, len(todo); next != prev; prev, next = next, len(todo) {
		for _, r := range sourceDoc.Relationships {
			if strings.HasPrefix(r.Related, "SPDXRef-File-") {
				continue
			}
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

	for _, r := range sourceDoc.Relationships {
		if _, ok := todo[r.Element]; ok {
			if strings.HasPrefix(r.Related, "SPDXRef-File-") {
				continue
			}
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

func mergeLicensingInfos(ctx context.Context, sourceDoc, targetDoc *Document) {
	var found bool
	for _, sourceinfo := range sourceDoc.LicensingInfos {
		found = false
		for _, targetinfo := range targetDoc.LicensingInfos {
			if targetinfo.LicenseID == sourceinfo.LicenseID {
				if targetinfo.ExtractedText != sourceinfo.ExtractedText {
					clog.FromContext(ctx).Warnf("source & target LicenseID %s differ in Text; please either update the package's license-path or use the correct LicenseID", targetinfo.LicenseID)
				}
				found = true
				break
			}
		}
		if !found {
			targetDoc.LicensingInfos = append(targetDoc.LicensingInfos, sourceinfo)
		}
	}
}

// ParseInternalSBOM opens an SBOM inside apks and
func (sx *SPDX) ParseInternalSBOM(opts *options.Options, path string) (*Document, error) {
	internalSBOM := &Document{}
	data, err := opts.FS.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("opening sbom file %s: %w", path, err)
	}

	if err := json.Unmarshal(data, internalSBOM); err != nil {
		return nil, fmt.Errorf("parsing internal apk sbom: %w", err)
	}

	// Fix up missing data, checkers require Originator &
	// Supplier, but older apks do not have it set, copy image
	// Supplier. Also files are stripped from sbom, thus set
	// filesAnalyzed to false and omit packageVerificationCode
	for i := range internalSBOM.Packages {
		if internalSBOM.Packages[i].Originator == "" {
			internalSBOM.Packages[i].Originator = supplier(opts)
		}
		if internalSBOM.Packages[i].Supplier == "" {
			internalSBOM.Packages[i].Supplier = internalSBOM.Packages[i].Originator
		}
		if internalSBOM.Packages[i].FilesAnalyzed {
			internalSBOM.Packages[i].FilesAnalyzed = false
		}
		if internalSBOM.Packages[i].VerificationCode != nil {
			internalSBOM.Packages[i].VerificationCode = nil
		}
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

func supplier(opts *options.Options) string {
	if opts.OS.Name == "" {
		return NOASSERTION
	}
	return "Organization: " + opts.OS.Name
}

func (sx *SPDX) imagePackage(opts *options.Options) (p *Package) {
	return &Package{
		ID: stringToIdentifier(fmt.Sprintf(
			"SPDXRef-Package-%s", opts.ImageInfo.ImageDigest,
		)),
		Name:             opts.ImageInfo.ImageDigest,
		Version:          opts.ImageInfo.ImageDigest,
		Supplier:         supplier(opts),
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

// LayerPackage returns a package describing the layer
func (sx *SPDX) layerPackage(opts *options.Options, layer v1.Descriptor) *Package {
	layerPackageName := hashToString(layer.Digest)
	mainPkgID := stringToIdentifier(layerPackageName)

	return &Package{
		ID:               fmt.Sprintf("SPDXRef-Package-%s", mainPkgID),
		Name:             layerPackageName,
		Version:          opts.OS.Version,
		FilesAnalyzed:    false,
		Description:      "apko operating system layer",
		DownloadLocation: NOASSERTION,
		Originator:       "",
		Supplier:         supplier(opts),
		Checksums:        []Checksum{},
		ExternalRefs: []ExternalRef{
			{
				Category: ExtRefPackageManager,
				Type:     ExtRefTypePurl,
				Locator: purl.NewPackageURL(
					purl.TypeOCI, "", opts.ImagePurlName(), hashToString(layer.Digest),
					nil, "",
				).String() + "?" + opts.LayerPurlQualifiers(layer).String(),
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
	Packages             []Package             `json:"packages"`
	Relationships        []Relationship        `json:"relationships"`
	ExternalDocumentRefs []ExternalDocumentRef `json:"externalDocumentRefs,omitempty"`
	LicensingInfos       []LicensingInfo       `json:"hasExtractedLicensingInfos,omitempty"`
}

type ExternalDocumentRef struct {
	Checksum           Checksum `json:"checksum"`
	ExternalDocumentID string   `json:"externalDocumentId"`
	SPDXDocument       string   `json:"spdxDocument"`
}

// Can also contain name, comment, seeAlso
type LicensingInfo struct {
	LicenseID     string `json:"licenseId"`
	ExtractedText string `json:"extractedText"`
}

type CreationInfo struct {
	Created            string   `json:"created"` // Date
	Creators           []string `json:"creators"`
	LicenseListVersion string   `json:"licenseListVersion"`
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
	ID               string                   `json:"SPDXID"`
	Name             string                   `json:"name"`
	Version          string                   `json:"versionInfo,omitempty"`
	FilesAnalyzed    bool                     `json:"filesAnalyzed"`
	LicenseConcluded string                   `json:"licenseConcluded,omitempty"`
	LicenseDeclared  string                   `json:"licenseDeclared,omitempty"`
	Description      string                   `json:"description,omitempty"`
	DownloadLocation string                   `json:"downloadLocation"`
	Originator       string                   `json:"originator,omitempty"`
	Supplier         string                   `json:"supplier,omitempty"`
	SourceInfo       string                   `json:"sourceInfo,omitempty"`
	CopyrightText    string                   `json:"copyrightText,omitempty"`
	AttributionText  string                   `json:"attributionText,omitempty"`
	PrimaryPurpose   string                   `json:"primaryPackagePurpose,omitempty"`
	Checksums        []Checksum               `json:"checksums,omitempty"`
	ExternalRefs     []ExternalRef            `json:"externalRefs,omitempty"`
	VerificationCode *PackageVerificationCode `json:"packageVerificationCode,omitempty"`
}

type PackageVerificationCode struct {
	Value string `json:"packageVerificationCodeValue,omitempty"`
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
	if len(opts.ImageInfo.Images) == 0 {
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
		Supplier:         supplier(opts),
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
			Supplier:         supplier(opts),
			FilesAnalyzed:    false,
			DownloadLocation: NOASSERTION,
			PrimaryPurpose:   "CONTAINER",
			Checksums: []Checksum{
				{
					Algorithm: "SHA256",
					Value:     info.Digest.DeepCopy().Hex,
				},
			},
			ExternalRefs: []ExternalRef{
				{
					Category: ExtRefPackageManager,
					Type:     ExtRefTypePurl,
					Locator: purl.NewPackageURL(
						purl.TypeOCI, "", opts.ImagePurlName(), info.Digest.DeepCopy().String(),
						nil, "",
					).String() + "?" + opts.ArchImagePurlQualifiers(&opts.ImageInfo.Images[i]).String(),
				},
			},
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

// addOperatingSystem adds a package describing the operating system
func addOperatingSystem(doc *Document, opts *options.Options) {
	osPackage := Package{
		ID:               fmt.Sprintf("SPDXRef-OperatingSystem-%s", stringToIdentifier(opts.OS.ID)),
		Name:             opts.OS.ID,
		Version:          opts.OS.Version,
		Supplier:         supplier(opts),
		FilesAnalyzed:    false,
		Description:      "Operating System",
		DownloadLocation: NOASSERTION,
		PrimaryPurpose:   "OPERATING_SYSTEM",
	}

	doc.Packages = append(doc.Packages, osPackage)
}

// addSourcePackage creates a package describing the source code
func addSourcePackage(vcsURL string, doc *Document, parent *Package, opts *options.Options) {
	version := ""
	checksums := []Checksum{}
	packageName := vcsURL
	if url, commitHash, found := strings.Cut(vcsURL, "@"); found {
		// This is git commit hash, currently defined as SHA1
		// SHA256 is only experimental in gitlab
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
		ID:               fmt.Sprintf("SPDXRef-Package-%s", stringToIdentifier(vcsURL)),
		Name:             packageName,
		Version:          version,
		Supplier:         supplier(opts),
		FilesAnalyzed:    false,
		PrimaryPurpose:   "SOURCE",
		Description:      "Image configuration source",
		DownloadLocation: downloadLocation,
		Checksums:        checksums,
		ExternalRefs:     []ExternalRef{},
	}

	// If this is a github package, add a purl to it:
	if after, ok := strings.CutPrefix(packageName, "github.com/"); ok {
		slug := after
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
