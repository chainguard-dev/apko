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
	"crypto/sha256"
	"encoding/hex"
	"testing"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
)

func createTestWheel(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatalf("creating file in zip: %v", err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatalf("writing file in zip: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("closing zip: %v", err)
	}
	return buf.Bytes()
}

func TestExtractWheel(t *testing.T) {
	wheelData := createTestWheel(t, map[string]string{
		"mypackage/__init__.py":              "# init",
		"mypackage/module.py":                "def hello(): pass",
		"mypackage-1.0.0.dist-info/METADATA": "Name: mypackage\nVersion: 1.0.0\n",
		"mypackage-1.0.0.dist-info/RECORD":   "",
	})

	fs := apkfs.NewMemFS()
	if err := fs.MkdirAll("usr/lib/python3.12/site-packages", 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	err := extractWheel(fs, wheelData, "usr/lib/python3.12/site-packages")
	if err != nil {
		t.Fatalf("extractWheel() error: %v", err)
	}

	// Check that files were extracted
	data, err := fs.ReadFile("usr/lib/python3.12/site-packages/mypackage/__init__.py")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "# init" {
		t.Errorf("content = %q, want %q", string(data), "# init")
	}

	data, err = fs.ReadFile("usr/lib/python3.12/site-packages/mypackage/module.py")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "def hello(): pass" {
		t.Errorf("content = %q, want %q", string(data), "def hello(): pass")
	}
}

func TestWriteInstallerFile(t *testing.T) {
	wheelData := createTestWheel(t, map[string]string{
		"mypackage/__init__.py":              "# init",
		"mypackage-1.0.0.dist-info/METADATA": "Name: mypackage\nVersion: 1.0.0\n",
	})

	fs := apkfs.NewMemFS()
	if err := fs.MkdirAll("usr/lib/python3.12/site-packages/mypackage-1.0.0.dist-info", 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	err := writeInstallerFile(fs, "usr/lib/python3.12/site-packages", wheelData)
	if err != nil {
		t.Fatalf("writeInstallerFile() error: %v", err)
	}

	data, err := fs.ReadFile("usr/lib/python3.12/site-packages/mypackage-1.0.0.dist-info/INSTALLER")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "apko\n" {
		t.Errorf("INSTALLER content = %q, want %q", string(data), "apko\n")
	}
}

func TestEvaluateMarkers(t *testing.T) {
	tests := []struct {
		name    string
		markers string
		extras  []string
		want    bool
	}{
		{"no markers", "", nil, true},
		{"extra not requested", `extra == "dev"`, nil, false},
		{"extra requested", `extra == "dev"`, []string{"dev"}, true},
		{"wrong extra", `extra == "dev"`, []string{"test"}, false},
		{"os_name posix", `os_name == "posix"`, nil, true},
		{"os_name nt", `os_name == "nt"`, nil, false},
		{"sys_platform linux", `sys_platform == "linux"`, nil, true},
		{"sys_platform win32", `sys_platform == "win32"`, nil, false},
		{"platform_system Linux", `platform_system == "Linux"`, nil, true},
		{"python_version", `python_version >= "3.8"`, nil, true},
		{"compound and true", `python_version >= "3.8" and os_name == "posix"`, nil, true},
		{"compound and false", `os_name == "nt" and python_version >= "3.8"`, nil, false},
		{"compound or true", `os_name == "nt" or os_name == "posix"`, nil, true},
		{"compound or false", `os_name == "nt" or sys_platform == "win32"`, nil, false},
		{"extra and platform", `extra == "dev" and os_name == "posix"`, []string{"dev"}, true},
		{"extra and wrong platform", `extra == "dev" and os_name == "nt"`, []string{"dev"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evaluateMarkers(tt.markers, tt.extras)
			if got != tt.want {
				t.Errorf("evaluateMarkers(%q, %v) = %v, want %v", tt.markers, tt.extras, got, tt.want)
			}
		})
	}
}

func TestVerifyChecksum(t *testing.T) {
	data := []byte("hello world")
	h := sha256.Sum256(data)
	validChecksum := "sha256:" + hex.EncodeToString(h[:])

	if err := verifyChecksum(data, validChecksum); err != nil {
		t.Errorf("verifyChecksum() with valid checksum: %v", err)
	}

	if err := verifyChecksum(data, "sha256:0000000000000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Error("verifyChecksum() with invalid checksum should return error")
	}

	if err := verifyChecksum(data, ""); err != nil {
		t.Error("verifyChecksum() with empty checksum should return nil")
	}
}
