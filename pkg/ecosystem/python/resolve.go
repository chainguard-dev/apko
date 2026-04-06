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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"regexp"
	"strings"

	"chainguard.dev/apko/pkg/apk/auth"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/ecosystem"

	"github.com/chainguard-dev/clog"
)

const defaultIndex = "https://pypi.org/simple/"
const pypiJSONBaseDefault = "https://pypi.org/pypi/"

// pypiJSONBaseOverride allows tests to redirect the JSON API to a mock server.
var pypiJSONBaseOverride string

func pypiJSONBase() string {
	if pypiJSONBaseOverride != "" {
		return pypiJSONBaseOverride
	}
	return pypiJSONBaseDefault
}

// packageSpec represents a parsed package requirement (e.g., "flask==3.0.0").
type packageSpec struct {
	Name     string
	Operator string // "==", ">=", "<=", "!=", "~=", ""
	Version  string
	Extras   []string
	Markers  string
}

// parsePackageSpec parses a PEP 508-style requirement string.
func parsePackageSpec(spec string) packageSpec {
	ps := packageSpec{}

	// Strip environment markers
	if idx := strings.Index(spec, ";"); idx != -1 {
		ps.Markers = strings.TrimSpace(spec[idx+1:])
		spec = strings.TrimSpace(spec[:idx])
	}

	// Strip extras
	if lbIdx := strings.Index(spec, "["); lbIdx != -1 {
		if rbIdx := strings.Index(spec, "]"); rbIdx != -1 {
			extras := spec[lbIdx+1 : rbIdx]
			ps.Extras = strings.Split(extras, ",")
			for i := range ps.Extras {
				ps.Extras[i] = strings.TrimSpace(ps.Extras[i])
			}
			spec = spec[:lbIdx] + spec[rbIdx+1:]
		}
	}

	spec = strings.TrimSpace(spec)

	// Handle parenthesized version constraints: "package (>=1.0)"
	if lpIdx := strings.Index(spec, "("); lpIdx != -1 {
		if rpIdx := strings.LastIndex(spec, ")"); rpIdx > lpIdx {
			ps.Name = strings.TrimSpace(spec[:lpIdx])
			inner := strings.TrimSpace(spec[lpIdx+1 : rpIdx])
			parts := strings.SplitN(inner, ",", 2)
			constraint := strings.TrimSpace(parts[0])
			for _, op := range []string{"~=", "==", "!=", ">=", "<=", ">", "<"} {
				if strings.HasPrefix(constraint, op) {
					ps.Operator = op
					ps.Version = strings.TrimSpace(constraint[len(op):])
					return ps
				}
			}
			return ps
		}
	}

	// Find the first operator by position in the string
	bestIdx := -1
	bestOp := ""
	for _, op := range []string{"~=", "==", "!=", ">=", "<=", ">", "<"} {
		idx := strings.Index(spec, op)
		if idx != -1 && (bestIdx == -1 || idx < bestIdx) {
			bestIdx = idx
			bestOp = op
		}
	}
	if bestIdx != -1 {
		ps.Name = strings.TrimSpace(spec[:bestIdx])
		ps.Operator = bestOp
		version := strings.TrimSpace(spec[bestIdx+len(bestOp):])
		if commaIdx := strings.Index(version, ","); commaIdx != -1 {
			version = version[:commaIdx]
		}
		ps.Version = version
		return ps
	}

	ps.Name = spec
	return ps
}

// normalizeName normalizes a Python package name per PEP 503.
func normalizeName(name string) string {
	return strings.ToLower(regexp.MustCompile(`[-_.]+`).ReplaceAllString(name, "-"))
}

// --- PyPI JSON API types ---

// pypiPackageJSON is the response from https://pypi.org/pypi/{name}/{version}/json
type pypiPackageJSON struct {
	Info pypiInfo  `json:"info"`
	URLs []pypiURL `json:"urls"`
}

type pypiInfo struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	RequiresDist []string `json:"requires_dist"`
}

type pypiURL struct {
	Filename    string      `json:"filename"`
	URL         string      `json:"url"`
	PackageType string      `json:"packagetype"`
	Digests     pypiDigests `json:"digests"`
}

type pypiDigests struct {
	SHA256 string `json:"sha256"`
}

// pypiVersionsJSON is a minimal parse of https://pypi.org/pypi/{name}/json
// to list available versions.
type pypiVersionsJSON struct {
	Releases map[string][]pypiURL `json:"releases"`
}

// --- Resolution ---

// resolvePackages resolves package specs to specific wheel URLs,
// including transitive dependencies discovered via the PyPI JSON API.
func resolvePackages(ctx context.Context, specs []packageSpec, indexes []string, pythonVersion string, arch types.Architecture, a auth.Authenticator) ([]ecosystem.ResolvedPackage, error) {
	log := clog.FromContext(ctx)

	if len(indexes) == 0 {
		indexes = []string{defaultIndex}
	}

	var resolved []ecosystem.ResolvedPackage
	seen := map[string]bool{}

	// BFS queue
	queue := make([]packageSpec, len(specs))
	copy(queue, specs)

	for len(queue) > 0 {
		spec := queue[0]
		queue = queue[1:]

		name := normalizeName(spec.Name)
		if seen[name] {
			continue
		}

		pkg, deps, err := resolveOneWithDeps(ctx, spec, indexes, pythonVersion, arch, a)
		if err != nil {
			return nil, fmt.Errorf("resolving %s: %w", spec.Name, err)
		}
		seen[name] = true
		resolved = append(resolved, pkg)
		log.Debugf("resolved %s==%s from %s", pkg.Name, pkg.Version, pkg.URL)

		for _, dep := range deps {
			if !seen[normalizeName(dep.Name)] {
				log.Debugf("discovered transitive dependency: %s (from %s)", dep.Name, pkg.Name)
				queue = append(queue, dep)
			}
		}
	}

	return resolved, nil
}

// resolveOneWithDeps resolves a package and returns both the resolved package
// and its transitive dependencies. It tries the PyPI JSON API first (which
// gives us clean metadata), falling back to the Simple API for non-PyPI indexes.
func resolveOneWithDeps(ctx context.Context, spec packageSpec, indexes []string, pythonVersion string, arch types.Architecture, a auth.Authenticator) (ecosystem.ResolvedPackage, []packageSpec, error) {
	// Try PyPI JSON API first — it gives us metadata + wheel URLs in one call
	if usesDefaultPyPI(indexes) {
		pkg, deps, err := resolveViaJSON(ctx, spec, pythonVersion, arch, a)
		if err == nil {
			return pkg, deps, nil
		}
		clog.FromContext(ctx).Debugf("JSON API failed for %s, falling back to Simple API: %v", spec.Name, err)
	}

	// Fall back to Simple API (downloads wheel to extract Requires-Dist for deps)
	pkg, deps, err := resolveViaSimple(ctx, spec, indexes, pythonVersion, arch, a)
	if err != nil {
		return ecosystem.ResolvedPackage{}, nil, err
	}
	return pkg, deps, nil
}

func usesDefaultPyPI(indexes []string) bool {
	if pypiJSONBaseOverride != "" {
		return true
	}
	for _, idx := range indexes {
		if strings.Contains(idx, "pypi.org") {
			return true
		}
	}
	return false
}

// resolveViaJSON resolves a package using the PyPI JSON API.
// Returns the resolved package and its parsed Requires-Dist as deps.
func resolveViaJSON(ctx context.Context, spec packageSpec, pythonVersion string, arch types.Architecture, a auth.Authenticator) (ecosystem.ResolvedPackage, []packageSpec, error) {
	name := normalizeName(spec.Name)

	// If we have an exact version, fetch that directly
	if spec.Operator == "==" {
		return resolveJSONVersion(ctx, name, spec.Name, spec.Version, pythonVersion, arch, a)
	}

	// Otherwise, list all versions and pick the best
	versionsURL := pypiJSONBase() + name + "/json"
	data, err := httpGet(ctx, versionsURL, a)
	if err != nil {
		return ecosystem.ResolvedPackage{}, nil, err
	}

	var versionsResp pypiVersionsJSON
	if err := json.Unmarshal(data, &versionsResp); err != nil {
		return ecosystem.ResolvedPackage{}, nil, fmt.Errorf("parsing PyPI versions JSON: %w", err)
	}

	// Find the best matching version
	bestVersion := ""
	for version := range versionsResp.Releases {
		if !matchesVersionSpec(version, spec) {
			continue
		}
		// Skip pre-releases unless explicitly requested
		if isPreRelease(version) && spec.Operator != "==" {
			continue
		}
		if bestVersion == "" || compareVersions(version, bestVersion) > 0 {
			bestVersion = version
		}
	}
	if bestVersion == "" {
		return ecosystem.ResolvedPackage{}, nil, fmt.Errorf("no matching version for %s%s%s", spec.Name, spec.Operator, spec.Version)
	}

	return resolveJSONVersion(ctx, name, spec.Name, bestVersion, pythonVersion, arch, a)
}

// resolveJSONVersion fetches a specific version from the PyPI JSON API.
func resolveJSONVersion(ctx context.Context, normalizedName, originalName, version, pythonVersion string, arch types.Architecture, a auth.Authenticator) (ecosystem.ResolvedPackage, []packageSpec, error) {
	versionURL := pypiJSONBase() + normalizedName + "/" + version + "/json"
	data, err := httpGet(ctx, versionURL, a)
	if err != nil {
		return ecosystem.ResolvedPackage{}, nil, err
	}

	var pkgResp pypiPackageJSON
	if err := json.Unmarshal(data, &pkgResp); err != nil {
		return ecosystem.ResolvedPackage{}, nil, fmt.Errorf("parsing PyPI JSON: %w", err)
	}

	// Find the best wheel from the URLs
	wheelURL, checksum, err := selectBestWheelFromJSON(pkgResp.URLs, pythonVersion, arch)
	if err != nil {
		return ecosystem.ResolvedPackage{}, nil, err
	}

	// Parse dependencies from requires_dist
	deps := make([]packageSpec, 0, len(pkgResp.Info.RequiresDist))
	for _, req := range pkgResp.Info.RequiresDist {
		dep := parsePackageSpec(req)
		if dep.Markers != "" && !evaluateMarkers(dep.Markers, nil) {
			continue
		}
		deps = append(deps, dep)
	}

	return ecosystem.ResolvedPackage{
		Ecosystem: "python",
		Name:      originalName,
		Version:   pkgResp.Info.Version,
		URL:       wheelURL,
		Checksum:  checksum,
	}, deps, nil
}

// selectBestWheelFromJSON picks the best compatible wheel from PyPI JSON API URLs.
func selectBestWheelFromJSON(urls []pypiURL, pythonVersion string, arch types.Architecture) (string, string, error) {
	var bestURL *pypiURL
	var bestParts wheelFileParts
	bestScore := -1

	for i, u := range urls {
		if u.PackageType != "bdist_wheel" {
			continue
		}
		parts, err := parseWheelFilename(u.Filename)
		if err != nil {
			continue
		}
		if !isCompatibleWheel(parts, pythonVersion, arch) {
			continue
		}

		score := wheelScore(parts, pythonVersion, arch)
		if bestURL == nil || score > bestScore {
			bestURL = &urls[i]
			bestParts = parts
			_ = bestParts // used for future scoring
			bestScore = score
		}
	}

	if bestURL == nil {
		return "", "", fmt.Errorf("no compatible wheel found")
	}

	checksum := ""
	if bestURL.Digests.SHA256 != "" {
		checksum = "sha256:" + bestURL.Digests.SHA256
	}
	return bestURL.URL, checksum, nil
}

// isPreRelease returns true if a version string looks like a pre-release.
func isPreRelease(version string) bool {
	v := strings.ToLower(version)
	for _, tag := range []string{"a", "b", "rc", "alpha", "beta", "dev", "pre"} {
		if strings.Contains(v, tag) {
			return true
		}
	}
	return false
}

// --- Simple API fallback (for non-PyPI indexes) ---

// wheelLink represents a parsed link from a PEP 503 Simple API response.
type wheelLink struct {
	Filename       string
	URL            string
	Checksum       string // "sha256:<hex>"
	RequiresPython string
	SignatureURL   string // optional: from data-signature attribute
	ProvenanceURL  string // optional: from data-provenance attribute
}

// parseSimpleIndex parses the HTML from a PEP 503 Simple Repository API response.
func parseSimpleIndex(body string, baseURL string) []wheelLink {
	// Use a regex that handles '>' inside quoted attribute values (e.g., data-requires-python=">=3.0").
	// The [^>]* approach breaks when attributes contain '>' characters.
	linkRe := regexp.MustCompile(`<a\s+(?:[^>"]*(?:"[^"]*")?)*href="([^"]*)"(?:[^>"]*(?:"[^"]*")?)*>([^<]*)</a>`)
	requiresPythonRe := regexp.MustCompile(`data-requires-python="([^"]*)"`)
	provenanceRe := regexp.MustCompile(`data-provenance="([^"]*)"`)
	signatureRe := regexp.MustCompile(`data-signature="([^"]*)"`)

	matches := linkRe.FindAllStringSubmatch(body, -1)
	links := make([]wheelLink, 0, len(matches))
	for _, match := range matches {
		href := match[1]
		filename := strings.TrimSpace(match[2])

		if !strings.HasSuffix(filename, ".whl") {
			continue
		}

		var checksum string
		if hashIdx := strings.Index(href, "#sha256="); hashIdx != -1 {
			checksum = "sha256:" + href[hashIdx+8:]
			href = href[:hashIdx]
		}

		linkURL := href
		if !strings.HasPrefix(href, "http://") && !strings.HasPrefix(href, "https://") {
			if base, err := neturl.Parse(baseURL); err == nil {
				if ref, err := neturl.Parse(href); err == nil {
					linkURL = base.ResolveReference(ref).String()
				}
			}
		}

		var requiresPython, provenanceURL, signatureURL string
		matchIdx := strings.Index(body, match[0])
		if matchIdx >= 0 {
			// match[0] starts with "<a", so matchIdx IS the tag start.
			tagStart := matchIdx
			if tagStart >= 0 {
				// Find the closing '>' of the <a> tag, skipping '>' inside quoted attributes.
				tag := ""
				rest := body[tagStart:]
				inQuote := false
				for j, c := range rest {
					if c == '"' {
						inQuote = !inQuote
					} else if c == '>' && !inQuote {
						tag = rest[:j+1]
						break
					}
				}
				if rpMatch := requiresPythonRe.FindStringSubmatch(tag); rpMatch != nil {
					requiresPython = strings.ReplaceAll(rpMatch[1], "&gt;", ">")
					requiresPython = strings.ReplaceAll(requiresPython, "&lt;", "<")
					requiresPython = strings.ReplaceAll(requiresPython, "&amp;", "&")
				}
				if pvMatch := provenanceRe.FindStringSubmatch(tag); pvMatch != nil {
					provenanceURL = pvMatch[1]
				}
				if sigMatch := signatureRe.FindStringSubmatch(tag); sigMatch != nil {
					signatureURL = sigMatch[1]
				}
			}
		}

		links = append(links, wheelLink{
			Filename:       filename,
			URL:            linkURL,
			Checksum:       checksum,
			RequiresPython: requiresPython,
			SignatureURL:   signatureURL,
			ProvenanceURL:  provenanceURL,
		})
	}

	return links
}

// resolveViaSimple resolves a package using the PEP 503 Simple API.
// After finding the best wheel, it downloads it to extract Requires-Dist
// metadata for transitive dependency resolution.
func resolveViaSimple(ctx context.Context, spec packageSpec, indexes []string, pythonVersion string, arch types.Architecture, a auth.Authenticator) (ecosystem.ResolvedPackage, []packageSpec, error) {
	name := normalizeName(spec.Name)

	for _, index := range indexes {
		indexURL := strings.TrimSuffix(index, "/") + "/" + name + "/"

		body, err := fetchSimpleIndex(ctx, indexURL, a)
		if err != nil {
			clog.FromContext(ctx).Debugf("index %s: %v", indexURL, err)
			continue
		}

		links := parseSimpleIndex(body, indexURL)
		if len(links) == 0 {
			continue
		}

		best, err := selectBestWheel(links, spec, pythonVersion, arch)
		if err != nil {
			continue
		}

		pkg := ecosystem.ResolvedPackage{
			Ecosystem:     "python",
			Name:          spec.Name,
			Version:       best.version,
			URL:           best.url,
			Checksum:      best.checksum,
			SignatureURL:  best.signatureURL,
			ProvenanceURL: best.provenanceURL,
		}

		// Download wheel to extract Requires-Dist for transitive deps.
		deps, err := extractDepsFromWheel(ctx, best.url, a)
		if err != nil {
			clog.FromContext(ctx).Debugf("could not extract deps from wheel for %s: %v", spec.Name, err)
		}

		return pkg, deps, nil
	}

	return ecosystem.ResolvedPackage{}, nil, fmt.Errorf("package %s not found in any index", spec.Name)
}

// extractDepsFromWheel downloads a wheel and parses its METADATA for Requires-Dist.
func extractDepsFromWheel(ctx context.Context, url string, a auth.Authenticator) ([]packageSpec, error) {
	data, err := httpGet(ctx, url, a)
	if err != nil {
		return nil, fmt.Errorf("downloading wheel: %w", err)
	}

	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("opening wheel as zip: %w", err)
	}

	for _, f := range reader.File {
		if !strings.HasSuffix(f.Name, ".dist-info/METADATA") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("opening METADATA: %w", err)
		}
		metadataBytes, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("reading METADATA: %w", err)
		}
		return parseRequiresDist(string(metadataBytes)), nil
	}

	return nil, nil
}

// parseRequiresDist extracts Requires-Dist entries from wheel METADATA content.
func parseRequiresDist(metadata string) []packageSpec {
	deps := make([]packageSpec, 0, strings.Count(metadata, "Requires-Dist: "))
	for line := range strings.SplitSeq(metadata, "\n") {
		line = strings.TrimRight(line, "\r")
		if !strings.HasPrefix(line, "Requires-Dist: ") {
			continue
		}
		req := strings.TrimPrefix(line, "Requires-Dist: ")
		dep := parsePackageSpec(req)
		if dep.Markers != "" && !evaluateMarkers(dep.Markers, nil) {
			continue
		}
		deps = append(deps, dep)
	}
	return deps
}

type selectedWheel struct {
	version       string
	url           string
	checksum      string
	signatureURL  string
	provenanceURL string
}

// selectBestWheel selects the best compatible wheel from Simple API links.
func selectBestWheel(links []wheelLink, spec packageSpec, pythonVersion string, arch types.Architecture) (selectedWheel, error) {
	var bestLink *wheelLink
	var bestParts wheelFileParts
	bestScore := -1

	for i, link := range links {
		parts, err := parseWheelFilename(link.Filename)
		if err != nil {
			continue
		}
		if !isCompatibleWheel(parts, pythonVersion, arch) {
			continue
		}
		if !matchesVersionSpec(parts.Version, spec) {
			continue
		}

		score := wheelScore(parts, pythonVersion, arch)
		if bestLink == nil || compareVersions(parts.Version, bestParts.Version) > 0 || (compareVersions(parts.Version, bestParts.Version) == 0 && score > bestScore) {
			bestLink = &links[i]
			bestParts = parts
			bestScore = score
		}
	}

	if bestLink == nil {
		return selectedWheel{}, fmt.Errorf("no compatible wheel found")
	}

	return selectedWheel{
		version:       bestParts.Version,
		url:           bestLink.URL,
		checksum:      bestLink.Checksum,
		signatureURL:  bestLink.SignatureURL,
		provenanceURL: bestLink.ProvenanceURL,
	}, nil
}

// --- Version comparison ---

func matchesVersionSpec(version string, spec packageSpec) bool {
	if spec.Operator == "" {
		return true
	}
	switch spec.Operator {
	case "==":
		return version == spec.Version
	case "!=":
		return version != spec.Version
	case ">=":
		return compareVersions(version, spec.Version) >= 0
	case "<=":
		return compareVersions(version, spec.Version) <= 0
	case ">":
		return compareVersions(version, spec.Version) > 0
	case "<":
		return compareVersions(version, spec.Version) < 0
	case "~=":
		if compareVersions(version, spec.Version) < 0 {
			return false
		}
		specParts := strings.Split(spec.Version, ".")
		verParts := strings.Split(version, ".")
		if len(specParts) < 2 || len(verParts) < 2 {
			return false
		}
		for i := 0; i < len(specParts)-1 && i < len(verParts); i++ {
			if verParts[i] != specParts[i] {
				return false
			}
		}
		return true
	}
	return false
}

func compareVersions(a, b string) int {
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")

	maxLen := len(aParts)
	maxLen = max(maxLen, len(bParts))

	for i := 0; i < maxLen; i++ {
		var aVal, bVal string
		if i < len(aParts) {
			aVal = aParts[i]
		} else {
			aVal = "0"
		}
		if i < len(bParts) {
			bVal = bParts[i]
		} else {
			bVal = "0"
		}
		if aVal == bVal {
			continue
		}
		aNum := parseVersionPart(aVal)
		bNum := parseVersionPart(bVal)
		if aNum != bNum {
			if aNum < bNum {
				return -1
			}
			return 1
		}
		if aVal < bVal {
			return -1
		}
		return 1
	}
	return 0
}

func parseVersionPart(s string) int {
	n := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		} else {
			break
		}
	}
	return n
}

// --- HTTP helpers ---

func fetchSimpleIndex(ctx context.Context, url string, a auth.Authenticator) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "text/html")

	if a != nil {
		if err := a.AddAuth(ctx, req); err != nil {
			return "", fmt.Errorf("adding auth for %s: %w", url, err)
		}
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d for %s", resp.StatusCode, url)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func httpGet(ctx context.Context, url string, a auth.Authenticator) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	if a != nil {
		if err := a.AddAuth(ctx, req); err != nil {
			return nil, fmt.Errorf("adding auth for %s: %w", url, err)
		}
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d for %s", resp.StatusCode, url)
	}

	return io.ReadAll(resp.Body)
}
