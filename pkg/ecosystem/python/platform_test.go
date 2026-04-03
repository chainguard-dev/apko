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

func TestPlatformTags(t *testing.T) {
	tests := []struct {
		arch     string
		wantLen  int
		wantAny  string // At least one tag should contain this
	}{
		{"amd64", 5, "x86_64"},
		{"arm64", 3, "aarch64"},
		{"arm/v7", 3, "armv7l"},
		{"386", 5, "i686"},
		{"ppc64le", 3, "ppc64le"},
		{"s390x", 3, "s390x"},
	}

	for _, tt := range tests {
		t.Run(tt.arch, func(t *testing.T) {
			tags := platformTags(types.ParseArchitecture(tt.arch))
			if len(tags) != tt.wantLen {
				t.Errorf("platformTags(%s) returned %d tags, want %d", tt.arch, len(tags), tt.wantLen)
			}
			found := false
			for _, tag := range tags {
				if contains(tag, tt.wantAny) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("platformTags(%s) = %v, none contain %q", tt.arch, tags, tt.wantAny)
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
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
		name    string
		wheel   wheelFileParts
		pyVer   string
		arch    string
		want    bool
	}{
		{
			name:  "pure python wheel is always compatible",
			wheel: wheelFileParts{PythonTag: "py3", ABITag: "none", PlatformTag: "any"},
			pyVer: "3.12",
			arch:  "amd64",
			want:  true,
		},
		{
			name:  "cpython binary for matching arch",
			wheel: wheelFileParts{PythonTag: "cp312", ABITag: "cp312", PlatformTag: "manylinux_2_17_x86_64"},
			pyVer: "3.12",
			arch:  "amd64",
			want:  true,
		},
		{
			name:  "cpython binary for wrong arch",
			wheel: wheelFileParts{PythonTag: "cp312", ABITag: "cp312", PlatformTag: "manylinux_2_17_aarch64"},
			pyVer: "3.12",
			arch:  "amd64",
			want:  false,
		},
		{
			name:  "wrong python version",
			wheel: wheelFileParts{PythonTag: "cp311", ABITag: "cp311", PlatformTag: "any"},
			pyVer: "3.12",
			arch:  "amd64",
			want:  false,
		},
		{
			name:  "abi3 is compatible",
			wheel: wheelFileParts{PythonTag: "cp312", ABITag: "abi3", PlatformTag: "manylinux_2_17_x86_64"},
			pyVer: "3.12",
			arch:  "amd64",
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isCompatibleWheel(tt.wheel, tt.pyVer, types.ParseArchitecture(tt.arch))
			if got != tt.want {
				t.Errorf("isCompatibleWheel() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWheelScore(t *testing.T) {
	pureWheel := wheelFileParts{PythonTag: "py3", ABITag: "none", PlatformTag: "any"}
	binaryWheel := wheelFileParts{PythonTag: "cp312", ABITag: "cp312", PlatformTag: "manylinux_2_17_x86_64"}

	pureScore := wheelScore(pureWheel, "3.12", types.ParseArchitecture("amd64"))
	binaryScore := wheelScore(binaryWheel, "3.12", types.ParseArchitecture("amd64"))

	if binaryScore <= pureScore {
		t.Errorf("binary wheel score (%d) should be higher than pure wheel score (%d)", binaryScore, pureScore)
	}
}
