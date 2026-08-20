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
	"context"
	"errors"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	ggcrtypes "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/build/types"
)

func TestGenerateIndex(t *testing.T) {

}

func TestGenerateDockerIndex(t *testing.T) {

}

func TestBuildIndex(t *testing.T) {

}

// erofs/erofs-image-spec §5.4 requires `erofs` in os.features in two places:
// the image config, and the index platform descriptor when the image is
// referenced from an index. apko always emits an index, so a consumer that
// filters on the index platform without fetching configs would otherwise never
// see the signal.
func TestGenerateIndex_PropagatesOSFeatures(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	arch := types.ParseArchitecture("amd64")

	buildImage := func(t *testing.T, ic types.ImageConfiguration, mt ggcrtypes.MediaType) v1.Image {
		t.Helper()
		img, err := BuildImageFromLayer(ctx, empty.Image, static.NewLayer([]byte("hello"), mt), ic, now, arch)
		require.NoError(t, err)
		return img
	}

	platformOf := func(t *testing.T, img v1.Image) *v1.Platform {
		t.Helper()
		_, idx, err := GenerateIndex(ctx, types.ImageConfiguration{}, map[types.Architecture]v1.Image{arch: img}, now)
		require.NoError(t, err)
		mf, err := idx.IndexManifest()
		require.NoError(t, err)
		require.Len(t, mf.Manifests, 1)
		require.NotNil(t, mf.Manifests[0].Platform, "index descriptor has no platform")
		return mf.Manifests[0].Platform
	}

	erofsImg := buildImage(t, types.ImageConfiguration{Format: types.LayerFormatErofs}, ggcrtypes.MediaType(types.ErofsLayerMediaType))
	require.Contains(t, platformOf(t, erofsImg).OSFeatures, "erofs",
		"index platform descriptor must declare erofs in os.features")

	// A tar build must not gain the feature, and the propagation must not
	// invent an empty OSFeatures slice where the config has none.
	tarImg := buildImage(t, types.ImageConfiguration{}, ggcrtypes.OCILayer)
	require.Nil(t, platformOf(t, tarImg).OSFeatures,
		"tar-format builds must not declare os.features on the index descriptor")
}

// configlessImage serves a real manifest but refuses every content-reaching
// method, mirroring a caller that stages only a leg's manifest blob and never
// its config or layers.
type configlessImage struct {
	v1.Image
}

var errNoContent = errors.New("content not staged")

func (configlessImage) ConfigFile() (*v1.ConfigFile, error) { return nil, errNoContent }
func (configlessImage) RawConfigFile() ([]byte, error)      { return nil, errNoContent }
func (configlessImage) Layers() ([]v1.Layer, error)         { return nil, errNoContent }

// os.features is optional, so an unreadable config must not abort index
// generation -- it only means there is no feature to carry. Reaching for
// config content unconditionally broke descriptor-plane callers that pass a
// manifest-only v1.Image; keep that from coming back.
func TestGenerateIndex_ToleratesUnreadableConfig(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	arch := types.ParseArchitecture("amd64")

	img, err := BuildImageFromLayer(ctx, empty.Image, static.NewLayer([]byte("hello"), ggcrtypes.OCILayer), types.ImageConfiguration{}, now, arch)
	require.NoError(t, err)

	imgs := map[types.Architecture]v1.Image{arch: configlessImage{Image: img}}

	_, idx, err := GenerateIndex(ctx, types.ImageConfiguration{}, imgs, now)
	require.NoError(t, err, "an unreadable config must not fail index generation")

	mf, err := idx.IndexManifest()
	require.NoError(t, err)
	require.Len(t, mf.Manifests, 1)
	require.NotNil(t, mf.Manifests[0].Platform, "index descriptor has no platform")
	require.Nil(t, mf.Manifests[0].Platform.OSFeatures,
		"an unreadable config must not invent os.features")
	require.Equal(t, arch.ToOCIPlatform(), mf.Manifests[0].Platform,
		"the descriptor platform must match the plain arch platform")

	// The docker manifest list path shares the same loop.
	_, didx, err := GenerateDockerIndex(ctx, types.ImageConfiguration{}, imgs, now)
	require.NoError(t, err, "an unreadable config must not fail docker index generation")
	dmf, err := didx.IndexManifest()
	require.NoError(t, err)
	require.Len(t, dmf.Manifests, 1)
}

// The propagation reads whatever os.features the finished config carries, and
// BuildImageFromLayers DeepCopies the base image's config -- so a base image
// that already declares features surfaces them on the index platform
// descriptor, for a tar build as much as an EROFS one. That is what §5.4 asks
// for (the descriptor should describe the image), and it changes the index
// digest for such builds, so pin it rather than leave it to be rediscovered.
func TestGenerateIndex_PropagatesOSFeaturesFromBaseImage(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	arch := types.ParseArchitecture("amd64")

	base, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{
		OSFeatures: []string{"example-feature"},
	})
	require.NoError(t, err)

	img, err := BuildImageFromLayer(ctx, base, static.NewLayer([]byte("hello"), ggcrtypes.OCILayer), types.ImageConfiguration{}, now, arch)
	require.NoError(t, err)

	cfg, err := img.ConfigFile()
	require.NoError(t, err)
	require.Equal(t, []string{"example-feature"}, cfg.OSFeatures,
		"the base image's os.features must survive into the built config")

	_, idx, err := GenerateIndex(ctx, types.ImageConfiguration{}, map[types.Architecture]v1.Image{arch: img}, now)
	require.NoError(t, err)
	mf, err := idx.IndexManifest()
	require.NoError(t, err)
	require.Len(t, mf.Manifests, 1)
	require.NotNil(t, mf.Manifests[0].Platform, "index descriptor has no platform")
	require.Equal(t, []string{"example-feature"}, mf.Manifests[0].Platform.OSFeatures,
		"a base image's os.features must reach the index platform descriptor")
}
