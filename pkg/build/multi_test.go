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

package build

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/apko/pkg/build/types"
)

// TestMultiArchSiblingFinishedFirst checks that an arch can still resolve
// packages that only exist in a build repository after a sibling arch has
// finished its build and rewritten its repositories file to the runtime
// repositories.
func TestMultiArchSiblingFinishedFirst(t *testing.T) {
	ctx := t.Context()

	buildRepo, err := filepath.Abs("testdata/packages")
	require.NoError(t, err)

	// A runtime repository that doesn't contain the requested package.
	runtimeRepo := t.TempDir()
	for _, arch := range []string{"x86_64", "aarch64"} {
		archive, err := apk.ArchiveFromIndex(&apk.APKIndex{})
		require.NoError(t, err)
		require.NoError(t, os.MkdirAll(filepath.Join(runtimeRepo, arch), 0o755))
		f, err := os.Create(filepath.Join(runtimeRepo, arch, "APKINDEX.tar.gz"))
		require.NoError(t, err)
		_, err = io.Copy(f, archive)
		require.NoError(t, err)
		require.NoError(t, f.Close())
	}

	archs := []types.Architecture{types.ParseArchitecture("amd64"), types.ParseArchitecture("arm64")}
	ma, err := NewMultiArch(ctx, archs,
		WithImageConfiguration(types.ImageConfiguration{
			Contents: types.ImageContents{
				BuildRepositories: []string{buildRepo},
				Repositories:      []string{runtimeRepo},
				Packages:          []string{"pretend-baselayout"},
			},
		}),
		WithIgnoreSignatures(true),
		WithoutDiskCache(),
	)
	require.NoError(t, err)

	// Build the first arch to completion, so the second one resolves after
	// its sibling rewrote the repositories file to the runtime repositories.
	first := ma.Contexts[archs[0]]
	_, _, err = first.BuildLayer(ctx)
	require.NoError(t, err)

	repos, err := first.fs.ReadFile("etc/apk/repositories")
	require.NoError(t, err)
	require.Equal(t, runtimeRepo+"\n", string(repos))

	_, _, err = ma.Contexts[archs[1]].BuildLayer(ctx)
	require.NoError(t, err)
}
