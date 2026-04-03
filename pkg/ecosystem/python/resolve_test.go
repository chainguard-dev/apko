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
	"context"
	"encoding/json"
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
		{"typing-extensions (>=4.10.0)", "typing-extensions", ">=", "4.10.0", ""},
		{"packaging (>=22.0,<25.0)", "packaging", ">=", "22.0", ""},
		{"mpmath<1.4,>=1.1.0", "mpmath", "<", "1.4", ""},
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

func TestParseSimpleIndexProvenance(t *testing.T) {
	body := `
<html><body>
<a href="foo-1.0.0-py3-none-any.whl#sha256=aaa" data-provenance="https://cgr.dev/prov/foo" data-signature="https://cgr.dev/sig/foo" data-requires-python="&gt;=3.8">foo-1.0.0-py3-none-any.whl</a>
<a href="bar-2.0.0-py3-none-any.whl#sha256=bbb">bar-2.0.0-py3-none-any.whl</a>
</body></html>
`
	links := parseSimpleIndex(body, "https://cgr.dev/simple/")
	if len(links) != 2 {
		t.Fatalf("expected 2 wheel links, got %d", len(links))
	}

	// First link should have provenance and signature
	if links[0].ProvenanceURL != "https://cgr.dev/prov/foo" {
		t.Errorf("links[0].ProvenanceURL = %q, want %q", links[0].ProvenanceURL, "https://cgr.dev/prov/foo")
	}
	if links[0].SignatureURL != "https://cgr.dev/sig/foo" {
		t.Errorf("links[0].SignatureURL = %q, want %q", links[0].SignatureURL, "https://cgr.dev/sig/foo")
	}
	if links[0].RequiresPython != ">=3.8" {
		t.Errorf("links[0].RequiresPython = %q, want %q", links[0].RequiresPython, ">=3.8")
	}

	// Second link should have empty provenance/signature
	if links[1].ProvenanceURL != "" {
		t.Errorf("links[1].ProvenanceURL = %q, want empty", links[1].ProvenanceURL)
	}
	if links[1].SignatureURL != "" {
		t.Errorf("links[1].SignatureURL = %q, want empty", links[1].SignatureURL)
	}
}

func TestParseRequiresDist(t *testing.T) {
	metadata := `Metadata-Version: 2.1
Name: vunnel
Version: 0.55.3
Requires-Dist: click>=8.0
Requires-Dist: PyYAML>=6.0
Requires-Dist: colorlog>=6.0
Requires-Dist: pytest; extra == "dev"
Requires-Dist: importlib-metadata>=4.0; python_version < "3.8"
`
	deps := parseRequiresDist(metadata)

	// Should get click, PyYAML, colorlog (not pytest which needs extra, not importlib-metadata gated on old python)
	names := map[string]bool{}
	for _, d := range deps {
		names[normalizeName(d.Name)] = true
	}
	if !names["click"] {
		t.Error("missing click")
	}
	if !names["pyyaml"] {
		t.Error("missing pyyaml")
	}
	if !names["colorlog"] {
		t.Error("missing colorlog")
	}
	if names["pytest"] {
		t.Error("should not include pytest (extra-gated)")
	}
	// importlib-metadata is python_version gated — evaluateMarkers is permissive for python_version
	// so it WILL be included (which is correct — we filter by wheel compatibility later)
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

func TestIsPreRelease(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		{"3.0.0", false},
		{"3.0.0rc1", true},
		{"3.0.0a1", true},
		{"3.0.0b2", true},
		{"3.0.0.dev1", true},
		{"1.14.0rc2", true},
	}
	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := isPreRelease(tt.version)
			if got != tt.want {
				t.Errorf("isPreRelease(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

// servePyPIJSON creates a mock server that serves PyPI JSON API responses.
func servePyPIJSON(t *testing.T, packages map[string]pypiPackageJSON) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	for name, pkg := range packages {
		name := normalizeName(name)
		pkg := pkg

		// Serve /pypi/{name}/{version}/json
		mux.HandleFunc("/pypi/"+name+"/"+pkg.Info.Version+"/json", func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(pkg)
		})

		// Serve /pypi/{name}/json (versions listing)
		mux.HandleFunc("/pypi/"+name+"/json", func(w http.ResponseWriter, r *http.Request) {
			resp := pypiVersionsJSON{
				Releases: map[string][]pypiURL{
					pkg.Info.Version: pkg.URLs,
				},
			}
			json.NewEncoder(w).Encode(resp)
		})

		// Serve Simple API as fallback
		mux.HandleFunc("/simple/"+name+"/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			html := "<html><body>\n"
			for _, u := range pkg.URLs {
				html += `<a href="` + u.URL + `#sha256=` + u.Digests.SHA256 + `">` + u.Filename + "</a>\n"
			}
			html += "</body></html>"
			w.Write([]byte(html))
		})
	}
	return httptest.NewServer(mux)
}

func TestResolveWithMockJSON(t *testing.T) {
	server := servePyPIJSON(t, map[string]pypiPackageJSON{
		"flask": {
			Info: pypiInfo{
				Name:    "Flask",
				Version: "3.0.0",
			},
			URLs: []pypiURL{{
				Filename:    "Flask-3.0.0-py3-none-any.whl",
				URL:         "https://files.example.com/Flask-3.0.0-py3-none-any.whl",
				PackageType: "bdist_wheel",
				Digests:     pypiDigests{SHA256: "abc123"},
			}},
		},
	})
	defer server.Close()

	// Override the JSON API base for the test
	origBase := pypiJSONBase
	defer func() { pypiJSONBaseOverride = ""; _ = origBase }()
	pypiJSONBaseOverride = server.URL + "/pypi/"

	specs := []packageSpec{{Name: "flask", Operator: "==", Version: "3.0.0"}}
	resolved, err := resolvePackages(context.Background(), specs, []string{server.URL + "/simple/"}, "3.12", types.ParseArchitecture("amd64"), nil)
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

func TestResolveTransitiveDeps(t *testing.T) {
	server := servePyPIJSON(t, map[string]pypiPackageJSON{
		"flask": {
			Info: pypiInfo{
				Name:    "Flask",
				Version: "3.0.0",
				RequiresDist: []string{
					"Werkzeug>=3.0.0",
					"click>=8.0",
					"devtools; extra == \"dev\"",
				},
			},
			URLs: []pypiURL{{
				Filename:    "Flask-3.0.0-py3-none-any.whl",
				URL:         "https://files.example.com/Flask-3.0.0-py3-none-any.whl",
				PackageType: "bdist_wheel",
				Digests:     pypiDigests{SHA256: "aaa"},
			}},
		},
		"werkzeug": {
			Info: pypiInfo{
				Name:    "Werkzeug",
				Version: "3.0.1",
				RequiresDist: []string{
					"MarkupSafe>=2.1.1",
				},
			},
			URLs: []pypiURL{{
				Filename:    "Werkzeug-3.0.1-py3-none-any.whl",
				URL:         "https://files.example.com/Werkzeug-3.0.1-py3-none-any.whl",
				PackageType: "bdist_wheel",
				Digests:     pypiDigests{SHA256: "bbb"},
			}},
		},
		"click": {
			Info: pypiInfo{
				Name:    "click",
				Version: "8.1.7",
			},
			URLs: []pypiURL{{
				Filename:    "click-8.1.7-py3-none-any.whl",
				URL:         "https://files.example.com/click-8.1.7-py3-none-any.whl",
				PackageType: "bdist_wheel",
				Digests:     pypiDigests{SHA256: "ccc"},
			}},
		},
		"markupsafe": {
			Info: pypiInfo{
				Name:    "MarkupSafe",
				Version: "2.1.5",
			},
			URLs: []pypiURL{{
				Filename:    "MarkupSafe-2.1.5-py3-none-any.whl",
				URL:         "https://files.example.com/MarkupSafe-2.1.5-py3-none-any.whl",
				PackageType: "bdist_wheel",
				Digests:     pypiDigests{SHA256: "ddd"},
			}},
		},
	})
	defer server.Close()

	pypiJSONBaseOverride = server.URL + "/pypi/"
	defer func() { pypiJSONBaseOverride = "" }()

	specs := []packageSpec{{Name: "flask", Operator: "==", Version: "3.0.0"}}
	resolved, err := resolvePackages(context.Background(), specs, []string{server.URL + "/simple/"}, "3.12", types.ParseArchitecture("amd64"), nil)
	if err != nil {
		t.Fatalf("resolvePackages() error: %v", err)
	}

	names := map[string]bool{}
	for _, pkg := range resolved {
		names[normalizeName(pkg.Name)] = true
	}

	for _, want := range []string{"flask", "werkzeug", "click", "markupsafe"} {
		if !names[want] {
			t.Errorf("missing transitive dependency: %s (resolved: %v)", want, names)
		}
	}
	if names["devtools"] {
		t.Error("should NOT include devtools (gated on extra)")
	}
	if len(resolved) != 4 {
		t.Errorf("expected 4 resolved packages, got %d: %v", len(resolved), names)
	}
}

func TestResolveSimpleApiFallback(t *testing.T) {
	// Test that non-PyPI indexes use the Simple API
	mux := http.NewServeMux()
	mux.HandleFunc("/simple/mypackage/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>
<a href="https://files.example.com/mypackage-1.0.0-py3-none-any.whl#sha256=abc">mypackage-1.0.0-py3-none-any.whl</a>
</body></html>`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	specs := []packageSpec{{Name: "mypackage", Operator: "==", Version: "1.0.0"}}
	// Use a non-pypi index so it doesn't try the JSON API
	resolved, err := resolvePackages(context.Background(), specs, []string{server.URL + "/simple/"}, "3.12", types.ParseArchitecture("amd64"), nil)
	if err != nil {
		t.Fatalf("resolvePackages() error: %v", err)
	}

	if len(resolved) != 1 {
		t.Fatalf("expected 1 resolved package, got %d", len(resolved))
	}
	if resolved[0].Version != "1.0.0" {
		t.Errorf("Version = %q, want %q", resolved[0].Version, "1.0.0")
	}
}
