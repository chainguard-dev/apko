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
	"archive/tar"
	"context"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/validate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/internal/cli"
	"chainguard.dev/apko/pkg/apk/expandapk/tarfs"
	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/sbom/generator/spdx"
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
		build.WithSBOMGenerators(spdx.New()),
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

	checkEarlyFiles(t, idx)

	// Not strictly necessary, but this will validate that the index is well-formed.
	require.NoError(t, validate.Index(idx))

	digest, err := idx.Digest()
	require.NoError(t, err)

	// This test will fail if we ever make a change in apko that changes the image.
	// Sometimes, this is intentional, and we need to change this and bump the version.
	want := "sha256:b0fb49df7ff53c00f076854213ec9b8d2ac1b04ff7bf872dc262487b849b12b0"
	require.Equal(t, want, digest.String())

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

func TestPublishLayering(t *testing.T) {
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

	config := filepath.Join("testdata", "layering.yaml")

	outputRefs := ""
	archs := types.ParseArchitectures([]string{"amd64", "arm64"})
	ropt := []remote.Option{remote.WithTransport(st)}
	opts := []build.Option{
		build.WithConfig(config, []string{}),
		build.WithTags(dst),
		build.WithSBOMGenerators(spdx.New()),
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

	checkEarlyFiles(t, idx)

	// Not strictly necessary, but this will validate that the index is well-formed.
	require.NoError(t, validate.Index(idx))

	digest, err := idx.Digest()
	require.NoError(t, err)

	// This test will fail if we ever make a change in apko that changes the image.
	// Sometimes, this is intentional, and we need to change this and bump the version.
	want := "sha256:ec5ec0579b8edabcea15445d3058aa0b844bf2fb1122d19b35f555251857b9df"
	require.Equal(t, want, digest.String())

	im, err := idx.IndexManifest()
	require.NoError(t, err)

	for _, m := range im.Manifests {
		child, err := idx.Image(m.Digest)
		require.NoError(t, err)

		cm, err := child.Manifest()
		require.NoError(t, err)

		require.Equal(t, 2, len(cm.Layers))

		tr := mutate.Extract(child)
		tmp, err := os.CreateTemp(t.TempDir(), "")
		require.NoError(t, err)
		size, err := io.Copy(tmp, tr)
		require.NoError(t, err)
		fsys, err := tarfs.New(tmp, size)
		require.NoError(t, err)

		b, err := fs.ReadFile(fsys, "etc/apk/repositories")
		require.NoError(t, err)

		if strings.Contains(string(b), "./packages") {
			t.Errorf("etc/apk/repositories contains build_repositories entry %q", "./packages")
		}
		if !strings.Contains(string(b), "apk.cgr.dev/runtime-only-repo") {
			t.Errorf("etc/apk/repositories does not contain expected runtime_repositories entry %q", "apk.cgr.dev/runtime-only-repo")
		}
	}
}

// checkEarlyFiles ensures that certain important files are present
// early in the image tarball, which can help with performance when
// extracting or using the image.
func checkEarlyFiles(t *testing.T, idx v1.ImageIndex) {
	mf, err := idx.IndexManifest()
	require.NoError(t, err)
	require.NotEmpty(t, len(mf.Manifests))

	img, err := idx.Image(mf.Manifests[0].Digest)
	require.NoError(t, err)

	rc := mutate.Extract(img)
	defer rc.Close()
	tr := tar.NewReader(rc)

	fileOffsets := map[string]int{}
	offset := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)

		fileOffsets[h.Name] = offset
		offset += int(h.Size)
	}

	requiredFiles := []string{
		"etc/apk/repositories",
		"etc/passwd",
		"etc/apko.json",
		"etc/os-release",
	}
	maxOffset := 4000 // files should be in the first N bytes of the extracted tar
	for _, f := range requiredFiles {
		pos, ok := fileOffsets[f]
		assert.True(t, ok, "file %q not found in image", f)
		t.Logf("file %q found at offset %d", f, pos)
		assert.Less(t, pos, maxOffset, "file %q found too late in image (pos %d)", f, pos)
	}
}
