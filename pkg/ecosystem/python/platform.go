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
	"fmt"
	"slices"
	"strings"

	"chainguard.dev/apko/pkg/build/types"
)

// platformTags returns the list of compatible wheel platform tags for the
// given architecture, ordered from most specific to least specific.
func platformTags(arch types.Architecture) []string {
	switch arch {
	case types.ParseArchitecture("amd64"):
		return []string{
			"manylinux_2_17_x86_64",
			"manylinux2014_x86_64",
			"manylinux_2_5_x86_64",
			"manylinux1_x86_64",
			"linux_x86_64",
		}
	case types.ParseArchitecture("arm64"):
		return []string{
			"manylinux_2_17_aarch64",
			"manylinux2014_aarch64",
			"linux_aarch64",
		}
	case types.ParseArchitecture("arm/v7"):
		return []string{
			"manylinux_2_17_armv7l",
			"manylinux2014_armv7l",
			"linux_armv7l",
		}
	case types.ParseArchitecture("arm/v6"):
		return []string{
			"manylinux_2_17_armv6l",
			"linux_armv6l",
		}
	case types.ParseArchitecture("386"):
		return []string{
			"manylinux_2_17_i686",
			"manylinux2014_i686",
			"manylinux_2_5_i686",
			"manylinux1_i686",
			"linux_i686",
		}
	case types.ParseArchitecture("ppc64le"):
		return []string{
			"manylinux_2_17_ppc64le",
			"manylinux2014_ppc64le",
			"linux_ppc64le",
		}
	case types.ParseArchitecture("s390x"):
		return []string{
			"manylinux_2_17_s390x",
			"manylinux2014_s390x",
			"linux_s390x",
		}
	case types.ParseArchitecture("riscv64"):
		return []string{
			"manylinux_2_17_riscv64",
			"linux_riscv64",
		}
	default:
		return []string{"any"}
	}
}

// wheelFileParts holds the parsed components of a wheel filename per PEP 427.
// Format: {distribution}-{version}(-{build tag})?-{python tag}-{abi tag}-{platform tag}.whl
type wheelFileParts struct {
	Distribution string
	Version      string
	BuildTag     string
	PythonTag    string
	ABITag       string
	PlatformTag  string
}

// parseWheelFilename parses a wheel filename per PEP 427.
func parseWheelFilename(filename string) (wheelFileParts, error) {
	name := strings.TrimSuffix(filename, ".whl")
	if name == filename {
		return wheelFileParts{}, fmt.Errorf("not a wheel file: %s", filename)
	}

	parts := strings.Split(name, "-")
	switch len(parts) {
	case 5:
		return wheelFileParts{
			Distribution: parts[0],
			Version:      parts[1],
			PythonTag:    parts[2],
			ABITag:       parts[3],
			PlatformTag:  parts[4],
		}, nil
	case 6:
		return wheelFileParts{
			Distribution: parts[0],
			Version:      parts[1],
			BuildTag:     parts[2],
			PythonTag:    parts[3],
			ABITag:       parts[4],
			PlatformTag:  parts[5],
		}, nil
	default:
		return wheelFileParts{}, fmt.Errorf("invalid wheel filename: %s", filename)
	}
}

// isCompatibleWheel checks whether a wheel file is compatible with the given
// Python version and architecture.
func isCompatibleWheel(w wheelFileParts, pythonVersion string, arch types.Architecture) bool {
	// Check python tag compatibility
	if !isCompatiblePythonTag(w.PythonTag, pythonVersion) {
		return false
	}

	// Check ABI compatibility
	if !isCompatibleABI(w.ABITag, pythonVersion) {
		return false
	}

	// Check platform compatibility
	return isCompatiblePlatform(w.PlatformTag, arch)
}

// isCompatiblePythonTag checks if the wheel's python tag is compatible.
// E.g., "py3", "cp312", "py2.py3"
func isCompatiblePythonTag(tag, pythonVersion string) bool {
	cpTag := "cp" + strings.ReplaceAll(pythonVersion, ".", "")
	for t := range strings.SplitSeq(tag, ".") {
		if t == "py3" || t == "py2.py3" || t == cpTag {
			return true
		}
	}
	return false
}

// isCompatibleABI checks if the wheel's ABI tag is compatible.
func isCompatibleABI(tag, pythonVersion string) bool {
	if tag == "none" {
		return true
	}
	cpTag := "cp" + strings.ReplaceAll(pythonVersion, ".", "")
	for t := range strings.SplitSeq(tag, ".") {
		if t == "abi3" || t == cpTag {
			return true
		}
	}
	return false
}

// isCompatiblePlatform checks if the wheel's platform tag is compatible.
func isCompatiblePlatform(tag string, arch types.Architecture) bool {
	if tag == "any" {
		return true
	}
	compatible := platformTags(arch)
	for t := range strings.SplitSeq(tag, ".") {
		if slices.Contains(compatible, t) {
			return true
		}
	}
	return false
}

// wheelScore returns a priority score for the wheel. Higher is better.
// Binary wheels for the exact platform are preferred over pure-Python wheels.
func wheelScore(w wheelFileParts, pythonVersion string, arch types.Architecture) int {
	score := 0

	// Prefer exact CPython tag over generic py3
	cpTag := "cp" + strings.ReplaceAll(pythonVersion, ".", "")
	for t := range strings.SplitSeq(w.PythonTag, ".") {
		if t == cpTag {
			score += 100
			break
		}
	}

	// Prefer specific ABI over none/abi3
	for t := range strings.SplitSeq(w.ABITag, ".") {
		switch t {
		case cpTag:
			score += 50
		case "abi3":
			score += 25
		}
	}

	// Prefer specific platform over any
	if w.PlatformTag != "any" {
		platTags := platformTags(arch)
		for i, pt := range platTags {
			for pp := range strings.SplitSeq(w.PlatformTag, ".") {
				if pp == pt {
					// More specific platforms (earlier in list) get higher scores
					score += 10 * (len(platTags) - i)
				}
			}
		}
	}

	return score
}
