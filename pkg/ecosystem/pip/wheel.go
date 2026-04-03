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
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
)

// extractWheel extracts a wheel (.whl) file into the filesystem at the given
// site-packages path. A .whl file is a ZIP archive.
func extractWheel(fsys apkfs.FullFS, wheelData []byte, sitePackagesPath string) error {
	reader, err := zip.NewReader(bytes.NewReader(wheelData), int64(len(wheelData)))
	if err != nil {
		return fmt.Errorf("opening wheel as zip: %w", err)
	}

	for _, f := range reader.File {
		targetPath := filepath.Join(sitePackagesPath, f.Name)

		if f.FileInfo().IsDir() {
			if err := fsys.MkdirAll(targetPath, 0755); err != nil {
				return fmt.Errorf("creating directory %s: %w", targetPath, err)
			}
			continue
		}

		// Ensure parent directory exists
		dir := filepath.Dir(targetPath)
		if err := fsys.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("creating parent directory %s: %w", dir, err)
		}

		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("opening %s in wheel: %w", f.Name, err)
		}

		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return fmt.Errorf("reading %s from wheel: %w", f.Name, err)
		}

		if err := fsys.WriteFile(targetPath, data, 0644); err != nil {
			return fmt.Errorf("writing %s: %w", targetPath, err)
		}
	}

	return nil
}

// writeInstallerFile writes the PEP 376 INSTALLER file into the .dist-info directory.
func writeInstallerFile(fsys apkfs.FullFS, sitePackagesPath string, wheelData []byte) error {
	reader, err := zip.NewReader(bytes.NewReader(wheelData), int64(len(wheelData)))
	if err != nil {
		return err
	}

	// Find the .dist-info directory
	for _, f := range reader.File {
		if strings.HasSuffix(f.Name, ".dist-info/METADATA") {
			distInfoDir := filepath.Dir(f.Name)
			installerPath := filepath.Join(sitePackagesPath, distInfoDir, "INSTALLER")
			return fsys.WriteFile(installerPath, []byte("apko\n"), 0644)
		}
	}

	return nil
}

// readMetadata reads the METADATA file from a wheel and returns its contents.
func readMetadata(wheelData []byte) (string, error) {
	reader, err := zip.NewReader(bytes.NewReader(wheelData), int64(len(wheelData)))
	if err != nil {
		return "", err
	}

	for _, f := range reader.File {
		if strings.HasSuffix(f.Name, ".dist-info/METADATA") {
			rc, err := f.Open()
			if err != nil {
				return "", err
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return "", err
			}
			return string(data), nil
		}
	}

	return "", fmt.Errorf("METADATA not found in wheel")
}

// parseRequiresDist extracts Requires-Dist entries from wheel METADATA content.
// Returns parsed package specs, filtering out entries with unsatisfiable markers.
func parseRequiresDist(metadata string, extras []string) []packageSpec {
	var deps []packageSpec
	for _, line := range strings.Split(metadata, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Requires-Dist:") {
			continue
		}
		req := strings.TrimSpace(strings.TrimPrefix(line, "Requires-Dist:"))
		spec := parsePackageSpec(req)

		// Skip deps gated on extras we didn't request
		if spec.Markers != "" && !evaluateMarkers(spec.Markers, extras) {
			continue
		}

		deps = append(deps, spec)
	}
	return deps
}

// evaluateMarkers performs a simplified evaluation of PEP 508 environment markers.
// It handles the most common cases:
//   - extra == "..." — only satisfied if the extra was requested
//   - os_name, sys_platform, platform_system — always Linux
//   - python_version — assumed satisfied (we already filtered wheels)
//   - implementation_name — "cpython"
//
// For compound markers (and/or), we do best-effort evaluation.
func evaluateMarkers(markers string, requestedExtras []string) bool {
	markers = strings.TrimSpace(markers)

	// Handle "or" — if any branch is true, the whole thing is true
	if orParts := splitMarkerOr(markers); len(orParts) > 1 {
		for _, part := range orParts {
			if evaluateMarkers(part, requestedExtras) {
				return true
			}
		}
		return false
	}

	// Handle "and" — all branches must be true
	if andParts := splitMarkerAnd(markers); len(andParts) > 1 {
		for _, part := range andParts {
			if !evaluateMarkers(part, requestedExtras) {
				return false
			}
		}
		return true
	}

	// Strip outer parens
	markers = strings.TrimSpace(markers)
	for strings.HasPrefix(markers, "(") && strings.HasSuffix(markers, ")") {
		markers = strings.TrimSpace(markers[1 : len(markers)-1])
	}

	// Parse single comparison: key op value
	key, op, value := parseMarkerExpr(markers)
	if key == "" {
		// Can't parse — be permissive, include the dep
		return true
	}

	switch key {
	case "extra":
		// Only include if the extra was explicitly requested
		for _, e := range requestedExtras {
			if matchMarkerOp(e, op, value) {
				return true
			}
		}
		return false
	case "os_name":
		return matchMarkerOp("posix", op, value)
	case "sys_platform":
		return matchMarkerOp("linux", op, value)
	case "platform_system":
		return matchMarkerOp("Linux", op, value)
	case "implementation_name":
		return matchMarkerOp("cpython", op, value)
	case "python_version", "python_full_version", "platform_machine",
		"platform_release", "platform_version", "implementation_version":
		// Be permissive for version-related markers — we've already
		// filtered wheels by Python version compatibility.
		return true
	default:
		// Unknown marker — be permissive
		return true
	}
}

// splitMarkerOr splits on " or " at the top level (not inside parens).
func splitMarkerOr(s string) []string {
	return splitMarkerBool(s, " or ")
}

// splitMarkerAnd splits on " and " at the top level (not inside parens).
func splitMarkerAnd(s string) []string {
	return splitMarkerBool(s, " and ")
}

func splitMarkerBool(s, sep string) []string {
	var parts []string
	depth := 0
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
		default:
			if depth == 0 && i+len(sep) <= len(s) && s[i:i+len(sep)] == sep {
				parts = append(parts, strings.TrimSpace(s[start:i]))
				start = i + len(sep)
				i += len(sep) - 1
			}
		}
	}
	parts = append(parts, strings.TrimSpace(s[start:]))
	if len(parts) == 1 && parts[0] == s {
		return parts
	}
	return parts
}

// parseMarkerExpr parses "key op 'value'" or "'value' op key".
func parseMarkerExpr(expr string) (key, op, value string) {
	expr = strings.TrimSpace(expr)

	// Try patterns like: extra == "dev"  or  "linux" == sys_platform
	for _, operator := range []string{"===", "~=", "==", "!=", ">=", "<=", ">", "<", " in ", " not in "} {
		idx := strings.Index(expr, operator)
		if idx < 0 {
			continue
		}
		lhs := strings.TrimSpace(expr[:idx])
		rhs := strings.TrimSpace(expr[idx+len(operator):])

		lhs = stripQuotes(lhs)
		rhs = stripQuotes(rhs)

		// Figure out which side is the key vs the value
		if isMarkerVar(lhs) {
			return lhs, strings.TrimSpace(operator), rhs
		}
		if isMarkerVar(rhs) {
			return rhs, flipOp(strings.TrimSpace(operator)), lhs
		}
		// Both look like values — treat lhs as key
		return lhs, strings.TrimSpace(operator), rhs
	}
	return "", "", ""
}

func stripQuotes(s string) string {
	if len(s) >= 2 && ((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'')) {
		return s[1 : len(s)-1]
	}
	return s
}

func isMarkerVar(s string) bool {
	switch s {
	case "os_name", "sys_platform", "platform_machine", "platform_python_implementation",
		"platform_release", "platform_system", "platform_version",
		"python_version", "python_full_version", "implementation_name",
		"implementation_version", "extra":
		return true
	}
	return false
}

func flipOp(op string) string {
	switch op {
	case ">":
		return "<"
	case "<":
		return ">"
	case ">=":
		return "<="
	case "<=":
		return ">="
	}
	return op
}

func matchMarkerOp(actual, op, expected string) bool {
	switch op {
	case "==", "===":
		return actual == expected
	case "!=":
		return actual != expected
	case "in":
		return strings.Contains(expected, actual)
	case "not in":
		return !strings.Contains(expected, actual)
	case ">=":
		return actual >= expected
	case "<=":
		return actual <= expected
	case ">":
		return actual > expected
	case "<":
		return actual < expected
	default:
		return true
	}
}

// verifyChecksum verifies the SHA256 checksum of data against the expected value.
func verifyChecksum(data []byte, expected string) error {
	if expected == "" {
		return nil
	}

	prefix := "sha256:"
	if !strings.HasPrefix(expected, prefix) {
		return fmt.Errorf("unsupported checksum format: %s", expected)
	}
	expectedHex := expected[len(prefix):]

	h := sha256.Sum256(data)
	actualHex := hex.EncodeToString(h[:])

	if actualHex != expectedHex {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedHex, actualHex)
	}

	return nil
}
