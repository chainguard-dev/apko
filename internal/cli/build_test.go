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
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/validate"
	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/internal/cli"
	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/build/types"
)

func TestBuild(t *testing.T) {
	ctx := context.Background()
	tmp := t.TempDir()

	golden := filepath.Join("testdata", "golden")
	goldenSboms := filepath.Join(golden, "sboms")
	config := filepath.Join("testdata", "apko.yaml")

	archs := types.ParseArchitectures([]string{"amd64", "arm64"})
	opts := []build.Option{
		build.WithConfig(config, []string{}),
		build.WithSBOMFormats([]string{"spdx"}),
		build.WithTags("golden:latest"),
		build.WithAnnotations(map[string]string{
			"org.opencontainers.image.vendor": "Vendor",
			"org.opencontainers.image.title":  "Title",
		}),
	}

	sbomPath := filepath.Join(tmp, "sboms")
	err := os.MkdirAll(sbomPath, 0o750)
	require.NoError(t, err)

	err = cli.BuildCmd(ctx, "golden:latest", tmp, archs, []string{}, true, sbomPath, opts...)
	require.NoError(t, err)

	root, err := layout.ImageIndexFromPath(tmp)
	require.NoError(t, err)

	gold, err := layout.ImageIndexFromPath(golden)
	require.NoError(t, err)

	// Not strictly necessary, but this will validate that the index is well-formed.
	require.NoError(t, validate.Index(root))
	require.NoError(t, validate.Index(gold))

	// TODO: We should diff manifests and layer contents.
	got, err := root.Digest()
	require.NoError(t, err)

	want, err := gold.Digest()
	require.NoError(t, err)

	require.Equal(t, want, got)

	// Check that the sbomPath is not empty.
	sboms, err := os.ReadDir(goldenSboms)
	require.NoError(t, err)
	require.NotEmpty(t, sboms)

	for _, s := range sboms {
		goldSbom := filepath.Join(goldenSboms, s.Name())
		sbom := filepath.Join(sbomPath, s.Name())

		want, err := os.ReadFile(goldSbom)
		require.NoError(t, err)

		got, err := os.ReadFile(sbom)
		require.NoError(t, err)

		if bytes.Equal(want, got) {
			continue
		}

		// https://github.com/google/go-cmp/issues/224#issuecomment-650429859
		transformJSON := cmp.FilterValues(func(x, y []byte) bool {
			return json.Valid(x) && json.Valid(y)
		}, cmp.Transformer("ParseJSON", func(in []byte) (out any) {
			if err := json.Unmarshal(in, &out); err != nil {
				panic(err) // should never occur given previous filter to ensure valid JSON
			}
			return out
		}))

		if diff := cmp.Diff(want, got, transformJSON); diff != "" {
			t.Errorf("Mismatched SBOMs (-%q +%q):\n%s", goldSbom, sbom, diff)
		}
	}
}

func TestBuildWithBase(t *testing.T) {
	// top_image golden file can be regenerated using ./internal/cli/testdata/regenerate_golden_top_image.sh script.

	// TODO(sfc-gh-mhazy) Check sboms after base image support is reflected in them.

	ctx := context.Background()
	tmp := t.TempDir()
	apkoTempDir := t.TempDir()

	golden := filepath.Join("testdata", "top_image")
	config := filepath.Join("testdata", "image_on_top.apko.yaml")
	lockfile := filepath.Join("testdata", "image_on_top.apko.lock.json")

	archs := types.ParseArchitectures([]string{"amd64", "arm64"})
	opts := []build.Option{build.WithConfig(config, []string{}), build.WithSBOMFormats([]string{"spdx"}), build.WithTags("golden_top:latest"), build.WithLockFile(lockfile), build.WithTempDir(apkoTempDir)}

	sbomPath := filepath.Join(tmp, "sboms")
	err := os.MkdirAll(sbomPath, 0o750)
	require.NoError(t, err)

	err = cli.BuildCmd(ctx, "golden_top:latest", tmp, archs, []string{}, true, sbomPath, opts...)
	require.NoError(t, err)

	root, err := layout.ImageIndexFromPath(tmp)
	require.NoError(t, err)

	gold, err := layout.ImageIndexFromPath(golden)
	require.NoError(t, err)

	// Not strictly necessary, but this will validate that the index is well-formed.
	require.NoError(t, validate.Index(root))
	require.NoError(t, validate.Index(gold))

	// TODO: We should diff manifests and layer contents.
	got, err := root.Digest()
	require.NoError(t, err)

	want, err := gold.Digest()
	require.NoError(t, err)

	require.Equal(t, want, got)
}
