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
	opts := []build.Option{build.WithConfig(config), build.WithTags(dst), build.WithSBOMFormats(sbom.DefaultOptions.Formats)}
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
	want := "sha256:5c5c59f1ab1da18a9abb4ff5cac4bb6b96c97f94c6e42b32da8ea7ef68c2fbab"
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
	swant := "sha256:a341a573dc27304f90d13505b3c9e5ad157a6b9167c96b282f295fbfba27980d"
	require.Equal(t, swant, got)

	im, err := idx.IndexManifest()
	require.NoError(t, err)

	// We also want to check the children SBOMs because the index SBOM does not have
	// references to the children SBOMs, just the children!
	wantBoms := []string{
		"sha256:a787a5c9bd6e02417803c3dc599d5c6bda675d87ae976e9161f2e726e3d6e70c",
		"sha256:d7feace7fad7eeae41f8c12de6242e9daf2f725596bbbf4bb29d4d2eeedba9ee",
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
