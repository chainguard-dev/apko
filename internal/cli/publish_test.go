// Copyright 2023 Chainguard, Inc.
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

package cli_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/validate"
	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/internal/cli"
	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/sbom"
)

func TestPublish(t *testing.T) {
	ctx := context.Background()
	tmp := t.TempDir()

	// Set up a registry that requires we see a magic header.
	// This allows us to make sure that remote options are getting passed
	// around to anything that hits the registry.
	r := registry.New()
	h := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		require.Equal(t, req.Header.Get("Magic"), "SecretValue")
		r.ServeHTTP(w, req)
	})
	s := httptest.NewServer(h)
	defer s.Close()
	u, err := url.Parse(s.URL)
	require.NoError(t, err)

	st := &sentinel{s.Client().Transport}
	dst := fmt.Sprintf("%s/test/publish", u.Host)

	config := filepath.Join("testdata", "apko.yaml")

	outputRefs := ""
	archs := types.ParseArchitectures([]string{"amd64", "arm64"})
	ropt := []remote.Option{remote.WithTransport(st)}
	opts := []build.Option{
		build.WithConfig(config, []string{}),
		build.WithTags(dst),
		build.WithSBOMFormats(sbom.DefaultOptions.Formats),
		build.WithAnnotations(map[string]string{"foo": "bar"}),
	}
	publishOpts := []cli.PublishOption{cli.WithTags(dst)}

	sbomPath := filepath.Join(tmp, "sboms")
	err = os.MkdirAll(sbomPath, 0o750)
	require.NoError(t, err)

	err = cli.PublishCmd(ctx, outputRefs, archs, ropt, sbomPath, opts, publishOpts)
	require.NoError(t, err)

	ref, err := name.ParseReference(dst)
	require.NoError(t, err)

	idx, err := remote.Index(ref, ropt...)
	require.NoError(t, err)

	// Not strictly necessary, but this will validate that the index is well-formed.
	require.NoError(t, validate.Index(idx))

	digest, err := idx.Digest()
	require.NoError(t, err)

	// This test will fail if we ever make a change in apko that changes the image.
	// Sometimes, this is intentional, and we need to change this and bump the version.
	want := "sha256:f341d69eddfffdd181935fe3cffe185fdf20778835b797089a818e0b1b540f93"
	require.Equal(t, want, digest.String())

	sdst := fmt.Sprintf("%s:%s.sbom", dst, strings.ReplaceAll(want, ":", "-"))
	sref, err := name.ParseReference(sdst)
	require.NoError(t, err)

	img, err := remote.Image(sref, ropt...)
	require.NoError(t, err)

	m, err := img.Manifest()
	require.NoError(t, err)

	// https://github.com/sigstore/cosign/issues/3120
	got := m.Layers[0].Digest.String()

	// This test will fail if we ever make a change in apko that changes the SBOM.
	// Sometimes, this is intentional, and we need to change this and bump the version.
	swant := "sha256:9d55cc224dadc94faf9f2fb974a55e10d523625df652954030f5f7f3210b427a"
	require.Equal(t, swant, got)

	im, err := idx.IndexManifest()
	require.NoError(t, err)

	// We also want to check the children SBOMs because the index SBOM does not have
	// references to the children SBOMs, just the children!
	wantBoms := []string{
		"sha256:c2edd8bec2034de667ac19701eed3032512190cf0d46300acef5afccee01dbd1",
		"sha256:94213634580d1d5feb97cdcc030f804d28ed6f8e77cde225b0aae53d5b927a33",
	}

	for i, m := range im.Manifests {
		childBom := fmt.Sprintf("%s:%s.sbom", dst, strings.ReplaceAll(m.Digest.String(), ":", "-"))
		childRef, err := name.ParseReference(childBom)
		require.NoError(t, err)

		img, err := remote.Image(childRef, ropt...)
		require.NoError(t, err)

		m, err := img.Manifest()
		require.NoError(t, err)

		got := m.Layers[0].Digest.String()
		require.Equal(t, wantBoms[i], got)
	}

	// Check that the sbomPath is not empty.
	sboms, err := os.ReadDir(sbomPath)
	require.NoError(t, err)
	require.NotEmpty(t, sboms)
}

type sentinel struct {
	rt http.RoundTripper
}

func (s *sentinel) RoundTrip(in *http.Request) (*http.Response, error) {
	in.Header.Set("Magic", "SecretValue")
	return s.rt.RoundTrip(in)
}
