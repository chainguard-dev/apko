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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeLayer struct {
	body        []byte
	role        string
	annotations map[string]string
	mediaType   string // override; default erofsLayerMediaType
}

// writeFakeOCILayout writes a minimal OCI image layout under root with one or
// more EROFS layers. Returns the path it wrote to.
func writeFakeOCILayout(t *testing.T, root string, layers []fakeLayer) string {
	t.Helper()
	blobsDir := filepath.Join(root, "blobs", "sha256")
	if err := os.MkdirAll(blobsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	type descriptor struct {
		MediaType   string            `json:"mediaType"`
		Size        int64             `json:"size"`
		Digest      string            `json:"digest"`
		Annotations map[string]string `json:"annotations,omitempty"`
		Platform    map[string]string `json:"platform,omitempty"`
	}

	writeBlob := func(body []byte) string {
		sum := sha256.Sum256(body)
		hexs := hex.EncodeToString(sum[:])
		if err := os.WriteFile(filepath.Join(blobsDir, hexs), body, 0o600); err != nil {
			t.Fatal(err)
		}
		return "sha256:" + hexs
	}

	// Image config — content doesn't matter for the reader, but the manifest
	// must reference a real blob.
	configDigest := writeBlob([]byte(`{"architecture":"amd64","os":"linux"}`))

	layerDescs := make([]descriptor, 0, len(layers))
	for _, l := range layers {
		mt := l.mediaType
		if mt == "" {
			mt = erofsLayerMediaType
		}
		dig := writeBlob(l.body)
		anns := map[string]string{}
		maps.Copy(anns, l.annotations)
		if l.role != "" {
			anns[erofsRoleAnnotation] = l.role
		}
		layerDescs = append(layerDescs, descriptor{
			MediaType:   mt,
			Size:        int64(len(l.body)),
			Digest:      dig,
			Annotations: anns,
		})
	}

	manifest := map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.manifest.v1+json",
		"config": descriptor{
			MediaType: "application/vnd.oci.image.config.v1+json",
			Size:      int64(len(`{"architecture":"amd64","os":"linux"}`)),
			Digest:    configDigest,
		},
		"layers": layerDescs,
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest := writeBlob(manifestBytes)

	index := map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.index.v1+json",
		"manifests": []descriptor{
			{
				MediaType: "application/vnd.oci.image.manifest.v1+json",
				Size:      int64(len(manifestBytes)),
				Digest:    manifestDigest,
				Annotations: map[string]string{
					annotationRefName: "latest",
				},
				Platform: map[string]string{"architecture": "amd64", "os": "linux"},
			},
		},
	}
	indexBytes, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "index.json"), indexBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestReadOCILayers_MultiLayer(t *testing.T) {
	dir := t.TempDir()
	writeFakeOCILayout(t, dir, []fakeLayer{
		{body: []byte("layer0-base"), role: erofsRoleOverlay},
		{body: []byte("layer1-mid"), role: erofsRoleOverlay},
		{body: []byte("layer2-top")},
	})

	refs, err := ReadOCILayers(dir, "", "amd64")
	if err != nil {
		t.Fatalf("ReadOCILayers: %v", err)
	}
	if len(refs) != 3 {
		t.Fatalf("got %d layers, want 3", len(refs))
	}
	for i, want := range []string{erofsRoleOverlay, erofsRoleOverlay, ""} {
		if refs[i].Role != want {
			t.Errorf("layer %d role: got %q want %q", i, refs[i].Role, want)
		}
	}
	for i, ref := range refs {
		if _, err := os.Stat(ref.BlobPath); err != nil {
			t.Errorf("layer %d blob missing: %v", i, err)
		}
	}
	// Bottom-up order.
	if !strings.HasSuffix(refs[0].BlobPath, fmt.Sprintf("%x", sha256.Sum256([]byte("layer0-base")))) {
		t.Errorf("layer 0 blob path does not match base layer: %s", refs[0].BlobPath)
	}
}

func TestReadOCILayers_SingleLayer(t *testing.T) {
	dir := t.TempDir()
	writeFakeOCILayout(t, dir, []fakeLayer{
		{body: []byte("only-layer")},
	})
	refs, err := ReadOCILayers(dir, "", "amd64")
	if err != nil {
		t.Fatalf("ReadOCILayers: %v", err)
	}
	if len(refs) != 1 || refs[0].Role != "" {
		t.Fatalf("got refs=%+v, want one layer with empty role", refs)
	}
}

func TestReadOCILayers_WrongMediaType(t *testing.T) {
	dir := t.TempDir()
	writeFakeOCILayout(t, dir, []fakeLayer{
		{body: []byte("not-erofs"), mediaType: "application/vnd.oci.image.layer.v1.tar+gzip"},
	})
	_, err := ReadOCILayers(dir, "", "amd64")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "EROFS") {
		t.Fatalf("error %q should mention EROFS", err)
	}
}

func TestReadOCILayers_BadRoleOrder(t *testing.T) {
	dir := t.TempDir()
	// First layer lacks role annotation: invalid.
	writeFakeOCILayout(t, dir, []fakeLayer{
		{body: []byte("a")},
		{body: []byte("b"), role: erofsRoleOverlay},
	})
	_, err := ReadOCILayers(dir, "", "amd64")
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("expected role-annotation error, got %v", err)
	}
}

func TestReadOCILayers_TagSelection(t *testing.T) {
	dir := t.TempDir()
	writeFakeOCILayout(t, dir, []fakeLayer{{body: []byte("x")}})
	if _, err := ReadOCILayers(dir, "latest", "amd64"); err != nil {
		t.Fatalf("tag match: %v", err)
	}
	if _, err := ReadOCILayers(dir, "no-such-tag", "amd64"); err == nil {
		t.Fatal("expected tag-not-found error")
	}
}
