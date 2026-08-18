// Copyright 2026 Chainguard, Inc.
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

package erofsmount

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSource(t *testing.T) {
	root := t.TempDir()

	blob := filepath.Join(root, "image.erofs")
	if err := os.WriteFile(blob, []byte("not really erofs"), 0o600); err != nil {
		t.Fatal(err)
	}
	ociDir := filepath.Join(root, "out")
	if err := os.MkdirAll(ociDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ociDir, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	plainDir := filepath.Join(root, "plain")
	if err := os.MkdirAll(plainDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// A directory whose name contains a colon and IS an OCI layout — bare-spec
	// match should pick it up via direct stat (no tag splitting).
	colonDir := filepath.Join(root, "weird:name")
	if err := os.MkdirAll(colonDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(colonDir, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		spec      string
		wantKind  Kind
		wantPath  string
		wantTag   string
		wantErr   bool
		errSubstr string
	}{
		{"blob-bare", blob, KindBlob, blob, "", false, ""},
		{"blob-prefix", "erofs:" + blob, KindBlob, blob, "", false, ""},
		{"oci-bare", ociDir, KindOCIDir, ociDir, "", false, ""},
		{"oci-bare-with-tag", ociDir + ":latest", KindOCIDir, ociDir, "latest", false, ""},
		{"oci-prefix", "oci:" + ociDir, KindOCIDir, ociDir, "", false, ""},
		{"oci-prefix-with-tag", "oci:" + ociDir + ":v1", KindOCIDir, ociDir, "v1", false, ""},
		{"oci-dir-prefix", "oci-dir:" + ociDir, KindOCIDir, ociDir, "", false, ""},
		{"oci-dir-prefix-with-tag", "oci-dir:" + ociDir + ":latest", KindOCIDir, ociDir, "latest", false, ""},
		{"plain-dir-rejected", plainDir, 0, "", "", true, "not an OCI image layout"},
		{"plain-dir-with-tag-rejected", plainDir + ":latest", 0, "", "", true, "not an OCI image layout"},
		{"missing", filepath.Join(root, "no-such-thing"), 0, "", "", true, "not found"},
		{"empty", "", 0, "", "", true, "empty source"},
		{"blob-tag-error", blob + ":latest", 0, "", "", true, "tag selector"},
		{"erofs-prefix-on-dir", "erofs:" + ociDir, 0, "", "", true, "not a regular file"},
		{"oci-prefix-on-blob", "oci:" + blob, 0, "", "", true, "not a directory"},
		{"colon-in-dir-name", colonDir, KindOCIDir, colonDir, "", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSource(tt.spec)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseSource(%q): want error, got %+v", tt.spec, got)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("ParseSource(%q): error %q does not contain %q", tt.spec, err, tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseSource(%q): %v", tt.spec, err)
			}
			if got.Kind != tt.wantKind {
				t.Errorf("kind: got %v, want %v", got.Kind, tt.wantKind)
			}
			wantAbs, _ := filepath.Abs(tt.wantPath)
			if got.Path != filepath.Clean(wantAbs) {
				t.Errorf("path: got %q, want %q", got.Path, wantAbs)
			}
			if got.Tag != tt.wantTag {
				t.Errorf("tag: got %q, want %q", got.Tag, tt.wantTag)
			}
			if got.Raw != tt.spec {
				t.Errorf("raw: got %q, want %q", got.Raw, tt.spec)
			}
		})
	}
}
