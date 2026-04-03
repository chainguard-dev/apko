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
	"net/http"
	"net/http/httptest"
	"testing"

	"chainguard.dev/apko/pkg/build/types"
)

func TestParsePackageSpec(t *testing.T) {
	tests := []struct {
		input   string
		name    string
		op      string
		version string
		markers string
	}{
		{"flask==3.0.0", "flask", "==", "3.0.0", ""},
		{"requests>=2.31.0", "requests", ">=", "2.31.0", ""},
		{"numpy", "numpy", "", "", ""},
		{"foo~=1.4.2", "foo", "~=", "1.4.2", ""},
		{"bar!=2.0", "bar", "!=", "2.0", ""},
		{`baz>=1.0; python_version>="3.8"`, "baz", ">=", "1.0", `python_version>="3.8"`},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			spec := parsePackageSpec(tt.input)
			if spec.Name != tt.name {
				t.Errorf("Name = %q, want %q", spec.Name, tt.name)
			}
			if spec.Operator != tt.op {
				t.Errorf("Operator = %q, want %q", spec.Operator, tt.op)
			}
			if spec.Version != tt.version {
				t.Errorf("Version = %q, want %q", spec.Version, tt.version)
			}
			if spec.Markers != tt.markers {
				t.Errorf("Markers = %q, want %q", spec.Markers, tt.markers)
			}
		})
	}
}

func TestNormalizeName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Flask", "flask"},
		{"my-package", "my-package"},
		{"my_package", "my-package"},
		{"My.Package", "my-package"},
		{"My---Package", "my-package"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeName(tt.input)
			if got != tt.want {
				t.Errorf("normalizeName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseSimpleIndex(t *testing.T) {
	body := `
<html><body>
<a href="Flask-3.0.0-py3-none-any.whl#sha256=abc123">Flask-3.0.0-py3-none-any.whl</a>
<a href="Flask-2.3.0-py3-none-any.whl#sha256=def456">Flask-2.3.0-py3-none-any.whl</a>
<a href="Flask-3.0.0.tar.gz#sha256=ghi789">Flask-3.0.0.tar.gz</a>
</body></html>
`
	links := parseSimpleIndex(body, "https://pypi.org/simple/flask/")
	if len(links) != 2 {
		t.Fatalf("expected 2 wheel links, got %d", len(links))
	}

	if links[0].Filename != "Flask-3.0.0-py3-none-any.whl" {
		t.Errorf("links[0].Filename = %q", links[0].Filename)
	}
	if links[0].Checksum != "sha256:abc123" {
		t.Errorf("links[0].Checksum = %q", links[0].Checksum)
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"2.0.0", "1.0.0", 1},
		{"1.0.0", "2.0.0", -1},
		{"1.10.0", "1.9.0", 1},
		{"1.0", "1.0.0", 0},
	}

	for _, tt := range tests {
		t.Run(tt.a+"_vs_"+tt.b, func(t *testing.T) {
			got := compareVersions(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("compareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestMatchesVersionSpec(t *testing.T) {
	tests := []struct {
		version string
		spec    packageSpec
		want    bool
	}{
		{"3.0.0", packageSpec{Operator: "==", Version: "3.0.0"}, true},
		{"3.0.1", packageSpec{Operator: "==", Version: "3.0.0"}, false},
		{"3.0.0", packageSpec{Operator: ">=", Version: "2.0.0"}, true},
		{"1.0.0", packageSpec{Operator: ">=", Version: "2.0.0"}, false},
		{"3.0.0", packageSpec{Operator: "", Version: ""}, true},
		{"1.4.3", packageSpec{Operator: "~=", Version: "1.4.2"}, true},
		{"2.0.0", packageSpec{Operator: "~=", Version: "1.4.2"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.version+"_"+tt.spec.Operator+tt.spec.Version, func(t *testing.T) {
			got := matchesVersionSpec(tt.version, tt.spec)
			if got != tt.want {
				t.Errorf("matchesVersionSpec(%q, %v) = %v, want %v", tt.version, tt.spec, got, tt.want)
			}
		})
	}
}

func TestResolveWithMockServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/simple/flask/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>
<a href="https://files.example.com/Flask-3.0.0-py3-none-any.whl#sha256=abc123">Flask-3.0.0-py3-none-any.whl</a>
<a href="https://files.example.com/Flask-2.3.0-py3-none-any.whl#sha256=def456">Flask-2.3.0-py3-none-any.whl</a>
</body></html>`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	specs := []packageSpec{{Name: "flask", Operator: "==", Version: "3.0.0"}}
	resolved, err := resolvePackages(context.Background(), specs, []string{server.URL + "/simple/"}, "3.12", types.ParseArchitecture("amd64"))
	if err != nil {
		t.Fatalf("resolvePackages() error: %v", err)
	}

	if len(resolved) != 1 {
		t.Fatalf("expected 1 resolved package, got %d", len(resolved))
	}

	if resolved[0].Name != "flask" {
		t.Errorf("Name = %q, want %q", resolved[0].Name, "flask")
	}
	if resolved[0].Version != "3.0.0" {
		t.Errorf("Version = %q, want %q", resolved[0].Version, "3.0.0")
	}
	if resolved[0].Checksum != "sha256:abc123" {
		t.Errorf("Checksum = %q, want %q", resolved[0].Checksum, "sha256:abc123")
	}
}
