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
	"strings"

	"chainguard.dev/apko/pkg/build/types"
)

// archToMachine maps OCI architecture strings to the Python/Linux machine
// string used in wheel platform tags.
var archToMachine = map[types.Architecture]string{
	types.ParseArchitecture("amd64"):   "x86_64",
	types.ParseArchitecture("arm64"):   "aarch64",
	types.ParseArchitecture("arm/v7"):  "armv7l",
	types.ParseArchitecture("arm/v6"):  "armv6l",
	types.ParseArchitecture("386"):     "i686",
	types.ParseArchitecture("ppc64le"): "ppc64le",
	types.ParseArchitecture("s390x"):   "s390x",
	types.ParseArchitecture("riscv64"): "riscv64",
	types.ParseArchitecture("loong64"): "loongarch64",
}

// isLinuxPlatformTag checks whether a single platform tag (e.g.
// "musllinux_1_2_x86_64") targets the given machine architecture and
// is compatible with the image's libc. musl images only accept musllinux
// wheels; glibc images only accept manylinux wheels.
func isLinuxPlatformTag(tag, machine string, libc string) bool {
	if !strings.HasSuffix(tag, "_"+machine) {
		return false
	}
	if tag == "linux_"+machine {
		return true
	}
	if libc == "musl" {
		return strings.HasPrefix(tag, "musllinux_")
	}
	return strings.HasPrefix(tag, "manylinux")
}

// isBinaryWheel returns true if the wheel targets a specific platform
// (not pure-python "any").
func isBinaryWheel(w wheelFileParts) bool {
	return w.PlatformTag != "any"
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
// Python version, architecture, and libc.
func isCompatibleWheel(w wheelFileParts, pythonVersion string, arch types.Architecture, libc string) bool {
	// Check python tag compatibility
	if !isCompatiblePythonTag(w.PythonTag, pythonVersion) {
		return false
	}

	// Check ABI compatibility
	if !isCompatibleABI(w.ABITag, pythonVersion) {
		return false
	}

	// Check platform compatibility
	return isCompatiblePlatform(w.PlatformTag, arch, libc)
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

// isCompatiblePlatform checks if the wheel's platform tag is compatible
// with the given architecture and libc, without version limits.
func isCompatiblePlatform(tag string, arch types.Architecture, libc string) bool {
	if tag == "any" {
		return true
	}
	machine, ok := archToMachine[arch]
	if !ok {
		return false
	}
	for t := range strings.SplitSeq(tag, ".") {
		if isLinuxPlatformTag(t, machine, libc) {
			return true
		}
	}
	return false
}

// isBetterWheel returns true if candidate is a better choice than current.
// Prefers binary wheels over pure-python.
func isBetterWheel(current, candidate wheelFileParts) bool {
	if !isBinaryWheel(current) && isBinaryWheel(candidate) {
		return true
	}
	return false
}
