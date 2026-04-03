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

package pip

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/ecosystem"

	"github.com/chainguard-dev/clog"
)

const defaultIndex = "https://pypi.org/simple/"

// packageSpec represents a parsed package requirement (e.g., "flask==3.0.0").
type packageSpec struct {
	Name       string
	Operator   string // "==", ">=", "<=", "!=", "~=", ""
	Version    string
	Extras     []string
	Markers    string
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

	for _, op := range []string{"~=", "==", "!=", ">=", "<=", ">", "<"} {
		if idx := strings.Index(spec, op); idx != -1 {
			ps.Name = strings.TrimSpace(spec[:idx])
			ps.Operator = op
			ps.Version = strings.TrimSpace(spec[idx+len(op):])
			return ps
		}
	}

	ps.Name = spec
	return ps
}

// normalizeName normalizes a Python package name per PEP 503.
func normalizeName(name string) string {
	return strings.ToLower(regexp.MustCompile(`[-_.]+`).ReplaceAllString(name, "-"))
}

// wheelLink represents a parsed link from a PEP 503 Simple API response.
type wheelLink struct {
	Filename string
	URL      string
	Checksum string // "sha256:<hex>"
	RequiresPython string
}

// parseSimpleIndex parses the HTML from a PEP 503 Simple Repository API response.
func parseSimpleIndex(body string, baseURL string) []wheelLink {
	var links []wheelLink

	// Simple regex-based parsing of <a> tags
	linkRe := regexp.MustCompile(`<a\s+[^>]*href="([^"]*)"[^>]*>([^<]*)</a>`)
	requiresPythonRe := regexp.MustCompile(`data-requires-python="([^"]*)"`)

	for _, match := range linkRe.FindAllStringSubmatch(body, -1) {
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

		// Resolve relative URLs
		url := href
		if !strings.HasPrefix(href, "http://") && !strings.HasPrefix(href, "https://") {
			url = strings.TrimSuffix(baseURL, "/") + "/" + strings.TrimPrefix(href, "/")
		}

		var requiresPython string
		// Check if there's a data-requires-python attribute in the full tag
		tagStart := strings.LastIndex(body[:strings.Index(body, match[0])+1], "<a")
		if tagStart >= 0 {
			tagEnd := strings.Index(body[tagStart:], ">") + tagStart
			tag := body[tagStart : tagEnd+1]
			if rpMatch := requiresPythonRe.FindStringSubmatch(tag); rpMatch != nil {
				requiresPython = strings.ReplaceAll(rpMatch[1], "&gt;", ">")
				requiresPython = strings.ReplaceAll(requiresPython, "&lt;", "<")
				requiresPython = strings.ReplaceAll(requiresPython, "&amp;", "&")
			}
		}

		links = append(links, wheelLink{
			Filename:       filename,
			URL:            url,
			Checksum:       checksum,
			RequiresPython: requiresPython,
		})
	}

	return links
}

// resolvePackages resolves package specs to specific wheel URLs using PEP 503.
func resolvePackages(ctx context.Context, specs []packageSpec, indexes []string, pythonVersion string, arch types.Architecture) ([]ecosystem.ResolvedPackage, error) {
	log := clog.FromContext(ctx)

	if len(indexes) == 0 {
		indexes = []string{defaultIndex}
	}

	var resolved []ecosystem.ResolvedPackage
	seen := map[string]bool{}

	for _, spec := range specs {
		if seen[normalizeName(spec.Name)] {
			continue
		}

		pkg, err := resolveOne(ctx, spec, indexes, pythonVersion, arch)
		if err != nil {
			return nil, fmt.Errorf("resolving %s: %w", spec.Name, err)
		}
		seen[normalizeName(spec.Name)] = true
		resolved = append(resolved, pkg)
		log.Debugf("resolved %s==%s from %s", pkg.Name, pkg.Version, pkg.URL)
	}

	return resolved, nil
}

// resolveOne resolves a single package spec to a wheel URL.
func resolveOne(ctx context.Context, spec packageSpec, indexes []string, pythonVersion string, arch types.Architecture) (ecosystem.ResolvedPackage, error) {
	name := normalizeName(spec.Name)

	for _, index := range indexes {
		indexURL := strings.TrimSuffix(index, "/") + "/" + name + "/"

		body, err := fetchSimpleIndex(ctx, indexURL)
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

		return ecosystem.ResolvedPackage{
			Ecosystem: "python",
			Name:      spec.Name,
			Version:   best.version,
			URL:       best.url,
			Checksum:  best.checksum,
		}, nil
	}

	return ecosystem.ResolvedPackage{}, fmt.Errorf("package %s not found in any index", spec.Name)
}

type selectedWheel struct {
	version  string
	url      string
	checksum string
}

// selectBestWheel selects the best compatible wheel from a list of links.
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
		version:  bestParts.Version,
		url:      bestLink.URL,
		checksum: bestLink.Checksum,
	}, nil
}

// matchesVersionSpec checks if a version matches the given spec.
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
		// Compatible release: ~=X.Y is equivalent to >=X.Y, ==X.*
		if compareVersions(version, spec.Version) < 0 {
			return false
		}
		specParts := strings.Split(spec.Version, ".")
		verParts := strings.Split(version, ".")
		if len(specParts) < 2 || len(verParts) < 2 {
			return false
		}
		// Major parts must match up to second-to-last
		for i := 0; i < len(specParts)-1 && i < len(verParts); i++ {
			if verParts[i] != specParts[i] {
				return false
			}
		}
		return true
	}
	return false
}

// compareVersions performs a simple version comparison.
// Returns -1, 0, or 1.
func compareVersions(a, b string) int {
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")

	maxLen := len(aParts)
	if len(bParts) > maxLen {
		maxLen = len(bParts)
	}

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
		// Try numeric comparison
		aNum := parseVersionPart(aVal)
		bNum := parseVersionPart(bVal)
		if aNum != bNum {
			if aNum < bNum {
				return -1
			}
			return 1
		}
		// Fall back to string comparison
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

// fetchSimpleIndex fetches the PEP 503 Simple API page for a package.
func fetchSimpleIndex(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "text/html")

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
