// Copyright 2022, 2023 Chainguard, Inc.
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

package oci

import (
	"archive/tar"
	"context"
	"io"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/static"
	ggcrtypes "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/build/types"
)

func TestGeneratePackageYAML(t *testing.T) {
	xpkg := map[string]any{
		"apiVersion": "meta.pkg.crossplane.io/v1",
		"kind":       "Provider",
		"metadata": map[string]any{
			"name": "my-provider",
			"annotations": map[string]any{
				"meta.crossplane.io/description": "My provider",
			},
		},
	}

	got, err := generatePackageYAML(xpkg)
	require.NoError(t, err)

	content := string(got)
	require.Contains(t, content, "apiVersion: meta.pkg.crossplane.io/v1")
	require.Contains(t, content, "kind: Provider")
	require.Contains(t, content, "name: my-provider")
	require.Contains(t, content, "meta.crossplane.io/description: My provider")
}

func TestBuildXpkgLayer_Deterministic(t *testing.T) {
	content := []byte("apiVersion: meta.pkg.crossplane.io/v1\nkind: Provider\n")
	created := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	layer1, err := buildXpkgLayer(content, created)
	require.NoError(t, err)

	layer2, err := buildXpkgLayer(content, created)
	require.NoError(t, err)

	digest1, err := layer1.Digest()
	require.NoError(t, err)

	digest2, err := layer2.Digest()
	require.NoError(t, err)

	require.Equal(t, digest1, digest2, "same inputs should produce same digest")
}

func TestBuildXpkgLayer_ContainsPackageYAML(t *testing.T) {
	content := []byte("test-content")
	created := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	layer, err := buildXpkgLayer(content, created)
	require.NoError(t, err)

	rc, err := layer.Uncompressed()
	require.NoError(t, err)
	defer rc.Close()

	tr := tar.NewReader(rc)
	hdr, err := tr.Next()
	require.NoError(t, err)
	require.Equal(t, "package.yaml", hdr.Name)
	require.Equal(t, int64(len(content)), hdr.Size)

	data, err := io.ReadAll(tr)
	require.NoError(t, err)
	require.Equal(t, content, data)

	_, err = tr.Next()
	require.ErrorIs(t, err, io.EOF, "should contain exactly one file")
}

func TestBuildImageFromLayers_WithXpkg(t *testing.T) {
	ctx := context.Background()
	created := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	appLayer := static.NewLayer([]byte("app-content"), ggcrtypes.OCILayer)

	ic := types.ImageConfiguration{
		Xpkg: map[string]any{
			"apiVersion": "meta.pkg.crossplane.io/v1",
			"kind":       "Provider",
			"metadata": map[string]any{
				"name": "my-provider",
			},
		},
	}

	img, err := BuildImageFromLayers(ctx, empty.Image, []v1.Layer{appLayer}, ic, created, types.ParseArchitecture("amd64"))
	require.NoError(t, err)

	manifest, err := img.Manifest()
	require.NoError(t, err)

	// Should have 2 layers: xpkg base layer + app layer
	require.Len(t, manifest.Layers, 2)

	// First layer should have the xpkg annotation
	require.Equal(t, XpkgLayerAnnotationValue, manifest.Layers[0].Annotations[XpkgLayerAnnotation])

	// Second layer should NOT have the xpkg annotation
	require.Empty(t, manifest.Layers[1].Annotations[XpkgLayerAnnotation])
}

func TestBuildImageFromLayers_WithoutXpkg(t *testing.T) {
	ctx := context.Background()
	created := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	appLayer := static.NewLayer([]byte("app-content"), ggcrtypes.OCILayer)

	ic := types.ImageConfiguration{}

	img, err := BuildImageFromLayers(ctx, empty.Image, []v1.Layer{appLayer}, ic, created, types.ParseArchitecture("amd64"))
	require.NoError(t, err)

	manifest, err := img.Manifest()
	require.NoError(t, err)

	// Should have exactly 1 layer (no xpkg layer prepended)
	require.Len(t, manifest.Layers, 1)
}
