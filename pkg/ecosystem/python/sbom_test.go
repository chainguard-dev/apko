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
	"encoding/json"
	"strings"
	"testing"

	"chainguard.dev/apko/pkg/ecosystem"
)

func TestIsChainguardSource(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"https://cgr.dev/chainguard-dev/libraries/python/simple/flask/Flask-3.0.0-py3-none-any.whl", true},
		{"https://packages.cgr.dev/os/x86_64/some-package.whl", true},
		{"https://pypi.org/simple/flask/Flask-3.0.0-py3-none-any.whl", false},
		{"https://files.pythonhosted.org/packages/Flask-3.0.0-py3-none-any.whl", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := isChainguardSource(tt.url)
			if got != tt.want {
				t.Errorf("isChainguardSource(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestGeneratePackageSBOM(t *testing.T) {
	pkg := ecosystem.ResolvedPackage{
		Ecosystem: "python",
		Name:      "flask",
		Version:   "3.0.0",
		URL:       "https://cgr.dev/chainguard-dev/libraries/python/simple/flask/Flask-3.0.0-py3-none-any.whl",
		Checksum:  "sha256:abc123",
	}

	data, err := generatePackageSBOM(pkg)
	if err != nil {
		t.Fatalf("generatePackageSBOM() error: %v", err)
	}

	var doc spdxDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshaling SBOM: %v", err)
	}

	if doc.SPDXVersion != "SPDX-2.3" {
		t.Errorf("SPDXVersion = %q, want %q", doc.SPDXVersion, "SPDX-2.3")
	}

	// Verify creators include Chainguard — this is what chainctl libraries verify checks.
	foundChainguard := false
	for _, c := range doc.CreationInfo.Creators {
		if strings.Contains(strings.ToLower(c), "chainguard") {
			foundChainguard = true
		}
	}
	if !foundChainguard {
		t.Errorf("creationInfo.creators %v does not contain Chainguard", doc.CreationInfo.Creators)
	}

	if len(doc.Packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(doc.Packages))
	}

	p := doc.Packages[0]
	if p.Name != "flask" {
		t.Errorf("package name = %q, want %q", p.Name, "flask")
	}
	if p.Version != "3.0.0" {
		t.Errorf("package version = %q, want %q", p.Version, "3.0.0")
	}
	if !strings.Contains(strings.ToLower(p.Supplier), "chainguard") {
		t.Errorf("supplier = %q, does not contain chainguard", p.Supplier)
	}
	if !strings.Contains(strings.ToLower(p.Originator), "chainguard") {
		t.Errorf("originator = %q, does not contain chainguard", p.Originator)
	}
	if p.DownloadLocation != pkg.URL {
		t.Errorf("downloadLocation = %q, want %q", p.DownloadLocation, pkg.URL)
	}
}
