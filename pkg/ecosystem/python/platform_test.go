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
	"testing"

	"chainguard.dev/apko/pkg/build/types"
)

func TestIsLinuxPlatformTag(t *testing.T) {
	tests := []struct {
		tag, machine string
		libc  string
		want         bool
	}{
		// musl accepts musllinux, rejects manylinux
		{"musllinux_1_2_x86_64", "x86_64", "musl", true},
		{"manylinux_2_17_x86_64", "x86_64", "musl", false},
		// glibc accepts manylinux, rejects musllinux
		{"manylinux_2_17_x86_64", "x86_64", "glibc", true},
		{"manylinux_2_99_x86_64", "x86_64", "glibc", true}, // no version ceiling
		{"manylinux2014_x86_64", "x86_64", "glibc", true},  // legacy alias
		{"manylinux1_i686", "i686", "glibc", true},          // legacy alias
		{"musllinux_1_2_x86_64", "x86_64", "glibc", false},
		// linux_ fallback works for both
		{"linux_x86_64", "x86_64", "musl", true},
		{"linux_x86_64", "x86_64", "glibc", true},
		// wrong machine or non-linux
		{"musllinux_1_2_aarch64", "x86_64", "musl", false},
		{"macosx_10_9_x86_64", "x86_64", "glibc", false},
		{"any", "x86_64", "glibc", false},
	}
	for _, tt := range tests {
		t.Run(tt.tag, func(t *testing.T) {
			if got := isLinuxPlatformTag(tt.tag, tt.machine, tt.libc); got != tt.want {
				t.Errorf("isLinuxPlatformTag(%q, %q, %v) = %v, want %v", tt.tag, tt.machine, tt.libc, got, tt.want)
			}
		})
	}
}

func TestIsBetterWheel(t *testing.T) {
	pure := wheelFileParts{PythonTag: "py3", ABITag: "none", PlatformTag: "any"}
	binary := wheelFileParts{PythonTag: "cp312", ABITag: "cp312", PlatformTag: "manylinux_2_17_x86_64"}

	if !isBetterWheel(pure, binary) {
		t.Error("binary wheel should be better than pure python")
	}
	if isBetterWheel(binary, pure) {
		t.Error("pure python should not be better than binary")
	}
	if isBetterWheel(binary, binary) {
		t.Error("identical wheels should not be better")
	}
}

func TestArchToMachine(t *testing.T) {
	// All standard architectures should have a mapping.
	for _, arch := range []string{"amd64", "arm64", "arm/v7", "arm/v6", "386", "ppc64le", "s390x", "riscv64", "loong64"} {
		if _, ok := archToMachine[types.ParseArchitecture(arch)]; !ok {
			t.Errorf("archToMachine missing %q", arch)
		}
	}
}

func TestParseWheelFilename(t *testing.T) {
	tests := []struct {
		filename string
		wantDist string
		wantVer  string
		wantPy   string
		wantABI  string
		wantPlat string
		wantErr  bool
	}{
		{
			filename: "Flask-3.0.0-py3-none-any.whl",
			wantDist: "Flask",
			wantVer:  "3.0.0",
			wantPy:   "py3",
			wantABI:  "none",
			wantPlat: "any",
		},
		{
			filename: "numpy-1.26.0-cp312-cp312-manylinux_2_17_x86_64.whl",
			wantDist: "numpy",
			wantVer:  "1.26.0",
			wantPy:   "cp312",
			wantABI:  "cp312",
			wantPlat: "manylinux_2_17_x86_64",
		},
		{
			filename: "notawheel.tar.gz",
			wantErr:  true,
		},
		{
			filename: "bad-name.whl",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			parts, err := parseWheelFilename(tt.filename)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if parts.Distribution != tt.wantDist {
				t.Errorf("Distribution = %q, want %q", parts.Distribution, tt.wantDist)
			}
			if parts.Version != tt.wantVer {
				t.Errorf("Version = %q, want %q", parts.Version, tt.wantVer)
			}
			if parts.PythonTag != tt.wantPy {
				t.Errorf("PythonTag = %q, want %q", parts.PythonTag, tt.wantPy)
			}
			if parts.ABITag != tt.wantABI {
				t.Errorf("ABITag = %q, want %q", parts.ABITag, tt.wantABI)
			}
			if parts.PlatformTag != tt.wantPlat {
				t.Errorf("PlatformTag = %q, want %q", parts.PlatformTag, tt.wantPlat)
			}
		})
	}
}

func TestIsCompatibleWheel(t *testing.T) {
	tests := []struct {
		name  string
		wheel wheelFileParts
		pyVer string
		arch  string
		libc  string
		want  bool
	}{
		{
			name:  "pure python wheel on glibc",
			wheel: wheelFileParts{PythonTag: "py3", ABITag: "none", PlatformTag: "any"},
			pyVer: "3.12", arch: "amd64", libc: "glibc", want: true,
		},
		{
			name:  "pure python wheel on musl",
			wheel: wheelFileParts{PythonTag: "py3", ABITag: "none", PlatformTag: "any"},
			pyVer: "3.12", arch: "amd64", libc: "musl", want: true,
		},
		{
			name:  "manylinux on glibc",
			wheel: wheelFileParts{PythonTag: "cp312", ABITag: "cp312", PlatformTag: "manylinux_2_17_x86_64"},
			pyVer: "3.12", arch: "amd64", libc: "glibc", want: true,
		},
		{
			name:  "manylinux on musl is rejected",
			wheel: wheelFileParts{PythonTag: "cp312", ABITag: "cp312", PlatformTag: "manylinux_2_17_x86_64"},
			pyVer: "3.12", arch: "amd64", libc: "musl", want: false,
		},
		{
			name:  "musllinux on musl",
			wheel: wheelFileParts{PythonTag: "cp312", ABITag: "cp312", PlatformTag: "musllinux_1_2_x86_64"},
			pyVer: "3.12", arch: "amd64", libc: "musl", want: true,
		},
		{
			name:  "musllinux on glibc is rejected",
			wheel: wheelFileParts{PythonTag: "cp312", ABITag: "cp312", PlatformTag: "musllinux_1_2_x86_64"},
			pyVer: "3.12", arch: "amd64", libc: "glibc", want: false,
		},
		{
			name:  "wrong arch",
			wheel: wheelFileParts{PythonTag: "cp312", ABITag: "cp312", PlatformTag: "manylinux_2_17_aarch64"},
			pyVer: "3.12", arch: "amd64", libc: "glibc", want: false,
		},
		{
			name:  "wrong python version",
			wheel: wheelFileParts{PythonTag: "cp311", ABITag: "cp311", PlatformTag: "any"},
			pyVer: "3.12", arch: "amd64", libc: "glibc", want: false,
		},
		{
			name:  "abi3 on glibc",
			wheel: wheelFileParts{PythonTag: "cp312", ABITag: "abi3", PlatformTag: "manylinux_2_17_x86_64"},
			pyVer: "3.12", arch: "amd64", libc: "glibc", want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isCompatibleWheel(tt.wheel, tt.pyVer, types.ParseArchitecture(tt.arch), tt.libc)
			if got != tt.want {
				t.Errorf("isCompatibleWheel() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWheelSelection(t *testing.T) {
	// When both pure and binary wheels are compatible, binary wins.
	pure := wheelFileParts{PythonTag: "py3", ABITag: "none", PlatformTag: "any"}
	binary := wheelFileParts{PythonTag: "cp312", ABITag: "cp312", PlatformTag: "manylinux_2_17_x86_64"}

	if !isCompatibleWheel(pure, "3.12", types.ParseArchitecture("amd64"), "glibc") {
		t.Fatal("pure wheel should be compatible")
	}
	if !isCompatibleWheel(binary, "3.12", types.ParseArchitecture("amd64"), "glibc") {
		t.Fatal("binary wheel should be compatible on glibc")
	}
	if !isBetterWheel(pure, binary) {
		t.Error("binary should be preferred over pure")
	}
}
