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
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/internal/cli"
	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/build/types"
)

func TestLock(t *testing.T) {
	ctx := context.Background()
	tmp := t.TempDir()

	golden := filepath.Join("testdata", "apko.lock.json")

	config := filepath.Join("testdata", "apko.yaml")
	archs := types.ParseArchitectures([]string{"amd64", "arm64"})
	opts := []build.Option{build.WithConfig(config)}
	outputPath := filepath.Join(tmp, "apko.lock.json")

	err := cli.LockCmd(ctx, outputPath, archs, opts)
	require.NoError(t, err)

	want, err := os.ReadFile(golden)
	require.NoError(t, err)
	got, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	if !bytes.Equal(want, got) {
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("Mismatched lock files: (-%q +%q):\n%s", golden, outputPath, diff)
		}
	}
}

func TestLockWithBaseImage(t *testing.T) {
	ctx := context.Background()
	tmp := t.TempDir()

	golden := filepath.Join("testdata", "image_on_top.apko.lock.json")

	config := filepath.Join("testdata", "image_on_top.apko.yaml")
	archs := types.ParseArchitectures([]string{"amd64", "arm64"})
	opts := []build.Option{build.WithConfig(config)}
	outputPath := filepath.Join(tmp, "apko.lock.json")

	err := cli.LockCmd(ctx, outputPath, archs, opts)
	require.NoError(t, err)

	want, err := os.ReadFile(golden)
	require.NoError(t, err)
	got, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	if !bytes.Equal(want, got) {
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("Mismatched lock files: (-%q +%q):\n%s", golden, outputPath, diff)
		}
	}
}
