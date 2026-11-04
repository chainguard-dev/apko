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
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/chainguard-dev/clog"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	purl "github.com/package-url/packageurl-go"
	"k8s.io/apimachinery/pkg/util/sets"
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

func (sx *SPDX) PredicateType() string {
	return "https://spdx.dev/Document"
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
			LicenseListVersion: "3.27",
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

	reserved := reservedIDs(opts.Packages)
	for _, pkg := range opts.Packages {
		if err := sx.processInternalApkSBOM(ctx, opts, doc, pkg, reserved); err != nil {
			return fmt.Errorf("describing package %q: %w", pkg.Name+"-"+pkg.Version, err)
		}
	}

	// Packages built from the same origin or upstream source share records, so
	// keep one copy. Two records under one ID that identify different components
	// would let one package's SBOM displace another's, so refuse them. Builds of
	// one source can still disagree on metadata such as its license; keep the
	// first record then.
	dedupedPackages := make([]Package, 0, len(doc.Packages))
	seen := make(map[string]int, len(doc.Packages))
	for _, p := range doc.Packages {
		j, ok := seen[p.ID]
		if !ok {
			seen[p.ID] = len(dedupedPackages)
			dedupedPackages = append(dedupedPackages, p)
			continue
		}
		prev := dedupedPackages[j]
		switch {
		case !sameIdentity(prev, p):
			return fmt.Errorf("SPDX ID %q names two packages that differ in name, version, "+
				"external references, or checksums: %q and %q",
				p.ID, prev.Name+"@"+prev.Version, p.Name+"@"+p.Version)
		case !sameMetadata(prev, p):
			clog.WarnContext(ctx, "records sharing an SPDX ID disagree on metadata; keeping the first",
				"ID", p.ID, "package", p.Name+"@"+p.Version)
		default:
			clog.DebugContext(ctx, "duplicate package ID found in SBOM, deduplicating package...", "ID", p.ID)
		}
	}
	doc.Packages = dedupedPackages

	if err := renderDoc(doc, path); err != nil {
		return fmt.Errorf("rendering document: %w", err)
	}

	return nil
}

// sameIdentity reports whether a and b identify one component to a scanner:
// the same name, version, external references, and digests, in any order.
func sameIdentity(a, b Package) bool {
	return a.Name == b.Name && a.Version == b.Version &&
		sets.New(a.ExternalRefs...).Equal(sets.New(b.ExternalRefs...)) &&
		sets.New(a.Checksums...).Equal(sets.New(b.Checksums...)) &&
		reflect.DeepEqual(a.VerificationCode, b.VerificationCode)
}

// sameMetadata reports whether a and b, which share an identity, also agree on
// every other field.
func sameMetadata(a, b Package) bool {
	a.ExternalRefs, a.Checksums = b.ExternalRefs, b.Checksums
	return reflect.DeepEqual(a, b)
}

// epochRe matches the -rN epoch that ends an apk version.
var epochRe = regexp.MustCompile(`-r\d+$`)

// locateApkSBOM returns the path of the SBOM that ipkg ships, or "" if it ships
// none. Only paths the installed database lists for ipkg count, so an SBOM that
// another package installs under ipkg's name is ignored.
func locateApkSBOM(fsys apkfs.ReaderFS, ipkg *apk.InstalledPackage) (string, error) {
	owned := map[string]struct{}{}
	for _, f := range ipkg.Files {
		if p := path.Clean("/" + f.Name); path.Dir(p) == apkSBOMdir {
			owned[p] = struct{}{}
		}
	}

	for _, s := range []string{
		fmt.Sprintf("%s/%s-%s.spdx.json", apkSBOMdir, ipkg.Name, ipkg.Version),
		fmt.Sprintf("%s/%s-%s.spdx.json", apkSBOMdir, ipkg.Name, epochRe.ReplaceAllString(ipkg.Version, "")),
		fmt.Sprintf("%s/%s.spdx.json", apkSBOMdir, ipkg.Name),
	} {
		if _, ok := owned[s]; !ok {
			continue
		}
		info, err := fsys.Stat(s)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("inspecting %q: %w", s, err)
		}
		if info.IsDir() {
			return "", fmt.Errorf("directory found at SBOM path %q", s)
		}
		return s, nil
	}

	return "", nil
}

// ProcessInternalApkSBOM adds to doc the packages that ipkg's own SBOM
// describes and everything they reach, or a record built from the apk database
// when ipkg ships no SBOM. It fails when the SBOM does not parse or describes
// anything other than ipkg.
func (sx *SPDX) ProcessInternalApkSBOM(ctx context.Context, opts *options.Options, doc *Document, ipkg *apk.InstalledPackage) error {
	return sx.processInternalApkSBOM(ctx, opts, doc, ipkg, reservedIDs(opts.Packages))
}

func (sx *SPDX) processInternalApkSBOM(ctx context.Context, opts *options.Options, doc *Document, ipkg *apk.InstalledPackage, reserved map[string]struct{}) error {
	sbomPath, err := locateApkSBOM(opts.FS, ipkg)
	if err != nil {
		return fmt.Errorf("inspecting FS for internal apk SBOM: %w", err)
	}
	if sbomPath == "" {
		clog.WarnContext(ctx, "package ships no SBOM; describing it from the apk database",
			"package", ipkg.Name, "version", ipkg.Version)
		p, licenses := installedPackage(opts, ipkg)
		doc.Packages = append(doc.Packages, p)
		mergeLicensingInfos(ctx, &Document{LicensingInfos: licenses}, doc)
		addContains(doc, []string{p.ID})
		return nil
	}

	apkSBOMDoc, err := sx.ParseInternalSBOM(opts, sbomPath)
	if err != nil {
		return err
	}

	described := describedIDs(apkSBOMDoc)
	if len(described) == 0 {
		return fmt.Errorf("%q describes no package", sbomPath)
	}
	todo := reachableIDs(apkSBOMDoc, described)
	if err := checkIdentity(apkSBOMDoc, ipkg, described, todo, reserved); err != nil {
		return fmt.Errorf("checking %q: %w", sbomPath, err)
	}
	if err := copySBOMElements(apkSBOMDoc, doc, todo); err != nil {
		return fmt.Errorf("copying element: %w", err)
	}

	mergeLicensingInfos(ctx, apkSBOMDoc, doc)
	addContains(doc, described)

	return nil
}

// packageID is the SPDX ID melange gives an apk's own record.
func packageID(ipkg *apk.InstalledPackage) string {
	return stringToIdentifier(fmt.Sprintf("SPDXRef-Package-%s-%s", ipkg.Name, ipkg.Version))
}

// reservedIDs returns the SPDX ID of each installed package's own record.
func reservedIDs(pkgs []*apk.InstalledPackage) map[string]struct{} {
	ids := make(map[string]struct{}, len(pkgs))
	for _, p := range pkgs {
		ids[packageID(p)] = struct{}{}
	}
	return ids
}

// describedIDs returns, sorted, the elements a document names through
// documentDescribes or a DESCRIBES relationship from the document itself.
func describedIDs(d *Document) []string {
	ids := slices.Clone(d.DocumentDescribes)
	for _, r := range d.Relationships {
		if r.Element == "SPDXRef-DOCUMENT" && r.Type == "DESCRIBES" {
			ids = append(ids, r.Related)
		}
	}
	slices.Sort(ids)
	return slices.Compact(ids)
}

// reachableIDs returns roots and every element they reach through
// relationships, other than files.
func reachableIDs(d *Document, roots []string) map[string]struct{} {
	edges := make(map[string][]string, len(d.Relationships))
	for _, r := range d.Relationships {
		if !strings.HasPrefix(r.Related, "SPDXRef-File-") {
			edges[r.Element] = append(edges[r.Element], r.Related)
		}
	}

	seen := make(map[string]struct{}, len(roots))
	queue := slices.Clone(roots)
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		queue = append(queue, edges[id]...)
	}
	return seen
}

// checkIdentity confirms that d describes ipkg alone: every described package
// and every package with an apk PURL names ipkg at its version, and nothing it
// reaches claims the SPDX ID of an installed package.
func checkIdentity(d *Document, ipkg *apk.InstalledPackage, described []string, reach, reserved map[string]struct{}) error {
	own := packageID(ipkg)
	byID := make(map[string]*Package, len(d.Packages))
	for i := range d.Packages {
		byID[d.Packages[i].ID] = &d.Packages[i]
	}

	for _, id := range described {
		p, ok := byID[id]
		if !ok {
			return fmt.Errorf("described element %q is not a package", id)
		}
		if !namesPackage(p.Name, p.Version, ipkg) {
			return fmt.Errorf("describes %q at %q rather than %q at %q", p.Name, p.Version, ipkg.Name, ipkg.Version)
		}
		purls, err := apkPURLs(p)
		if err != nil {
			return err
		}
		for _, u := range purls {
			// The PURL spec lowercases apk package names (pkg:apk/wolfi/libllvm-19
			// for the package libLLVM-19), so the PURL's name is compared
			// case-insensitively; the SPDX name above stays an exact match.
			if !namesPackageFold(u.Name, u.Version, ipkg) {
				return fmt.Errorf("package %q carries PURL %q", id, u.String())
			}
		}
		if _, ok := reserved[id]; ok && id != own {
			return fmt.Errorf("package %q uses the SPDX ID of another installed package", id)
		}
	}

	for i := range d.Packages {
		p := &d.Packages[i]
		if _, ok := reach[p.ID]; !ok || slices.Contains(described, p.ID) {
			continue
		}
		if _, ok := reserved[p.ID]; ok || p.ID == own {
			return fmt.Errorf("reachable package %q uses the SPDX ID of an installed package", p.ID)
		}
		purls, err := apkPURLs(p)
		if err != nil {
			return err
		}
		// Some generators catalog the package's own apk entry as a reachable package.
		// The PURL name is lowercased by the spec: compare it case-insensitively.
		for _, u := range purls {
			if !namesPackage(p.Name, p.Version, ipkg) || !namesPackageFold(u.Name, u.Version, ipkg) {
				return fmt.Errorf("reachable package %q carries apk PURL %q", p.ID, u.String())
			}
		}
	}

	return nil
}

// namesPackage reports whether name and version identify ipkg, with or without
// its epoch.
func namesPackage(name, version string, ipkg *apk.InstalledPackage) bool {
	return name == ipkg.Name &&
		(version == ipkg.Version || version == epochRe.ReplaceAllString(ipkg.Version, ""))
}

// namesPackageFold is namesPackage with a case-insensitive name comparison,
// for PURLs, whose apk names are lowercased by the spec.
func namesPackageFold(name, version string, ipkg *apk.InstalledPackage) bool {
	return strings.EqualFold(name, ipkg.Name) &&
		(version == ipkg.Version || version == epochRe.ReplaceAllString(ipkg.Version, ""))
}

// apkPURLs returns the pkg:apk PURLs among p's external references.
func apkPURLs(p *Package) ([]purl.PackageURL, error) {
	var out []purl.PackageURL
	for _, ref := range p.ExternalRefs {
		if ref.Type != ExtRefTypePurl {
			continue
		}
		u, err := purl.FromString(ref.Locator)
		if err != nil {
			if strings.HasPrefix(ref.Locator, "pkg:apk/") {
				return nil, fmt.Errorf("package %q carries malformed PURL %q: %w", p.ID, ref.Locator, err)
			}
			continue
		}
		if u.Type == "apk" {
			out = append(out, u)
		}
	}
	return out, nil
}

// installedPackage describes ipkg from its apk database entry, returning the
// extracted licenses its license expression references.
func installedPackage(opts *options.Options, ipkg *apk.InstalledPackage) (Package, []LicensingInfo) {
	qualifiers := map[string]string{}
	if arch := cmp.Or(ipkg.Arch, opts.ImageInfo.Arch.ToAPK()); arch != "" {
		qualifiers["arch"] = arch
	}
	license, refs := licenseExpression(ipkg.License)
	return Package{
		ID:               packageID(ipkg),
		Name:             ipkg.Name,
		Version:          ipkg.Version,
		LicenseConcluded: NOASSERTION,
		LicenseDeclared:  license,
		Description:      ipkg.Description,
		DownloadLocation: NOASSERTION,
		Originator:       supplier(opts),
		Supplier:         supplier(opts),
		SourceInfo:       "Package info from apk database",
		CopyrightText:    NOASSERTION,
		ExternalRefs: []ExternalRef{{
			Category: ExtRefPackageManager,
			Type:     ExtRefTypePurl,
			Locator: purl.NewPackageURL("apk", opts.OS.ID, ipkg.Name, ipkg.Version,
				purl.QualifiersFromMap(qualifiers), "").String(),
		}},
	}, refs
}

// addContains links the document root to each of ids, so tools that walk the
// graph from the root reach them.
func addContains(doc *Document, ids []string) {
	if len(doc.DocumentDescribes) == 0 {
		return
	}
	for _, id := range ids {
		doc.Relationships = append(doc.Relationships, Relationship{
			Element: doc.DocumentDescribes[0],
			Type:    "CONTAINS",
			Related: id,
		})
	}
}

// copySBOMElements copies the packages in todo, and the relationships from
// them other than to files, from sourceDoc to targetDoc.
func copySBOMElements(sourceDoc, targetDoc *Document, todo map[string]struct{}) error {
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
		return nil, fmt.Errorf("parsing internal apk sbom %q: %w", path, err)
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
			"SPDXRef-Package-Image-%s", opts.ImageInfo.ImageDigest,
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
		ID:               fmt.Sprintf("SPDXRef-Package-ImageLayer-%s", mainPkgID),
		Name:             layerPackageName,
		Version:          opts.OS.Version,
		FilesAnalyzed:    false,
		Description:      "apko operating system layer",
		DownloadLocation: NOASSERTION,
		PrimaryPurpose:   "CONTAINER",
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
			LicenseListVersion: "3.27",
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
