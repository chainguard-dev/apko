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

package cli

import (
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/build"
)

func TestBuildCPIOCmd(t *testing.T) {
	ctx := context.Background()

	// Minimal config — no packages, no repositories — keeps the
	// build fully offline and fast.
	configFile := filepath.Join(t.TempDir(), "apko.yaml")
	err := os.WriteFile(configFile, []byte("contents:\n  repositories:\n    - https://dl-cdn.alpinelinux.org/alpine/edge/main\n  packages: []\n"), 0644)
	require.NoError(t, err)

	t.Run("gz suffix produces gzip-compressed output", func(t *testing.T) {
		dest := filepath.Join(t.TempDir(), "out.cpio.gz")

		err := BuildCPIOCmd(ctx, dest, build.WithConfig(configFile, []string{}))
		require.NoError(t, err)

		f, err := os.Open(dest)
		require.NoError(t, err)
		defer f.Close()

		gzr, err := gzip.NewReader(f)
		require.NoError(t, err, "expected output to be valid gzip")
		defer gzr.Close()
	})

	t.Run("non-gz suffix produces plain cpio output", func(t *testing.T) {
		dest := filepath.Join(t.TempDir(), "out.cpio")

		err := BuildCPIOCmd(ctx, dest, build.WithConfig(configFile, []string{}))
		require.NoError(t, err)

		f, err := os.Open(dest)
		require.NoError(t, err)
		defer f.Close()

		_, err = gzip.NewReader(f)
		require.Error(t, err, "expected plain cpio, got gzip")
	})
}
