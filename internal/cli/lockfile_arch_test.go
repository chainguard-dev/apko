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

package cli_test

import (
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/internal/cli"
	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/sbom/generator/spdx"
)

// lockConfig locks config for archs the way `apko lock --arch=...` does and
// returns the path of the lock file.
func lockConfig(t *testing.T, config string, archs ...string) string {
	t.Helper()

	lockfile := filepath.Join(t.TempDir(), "apko.lock.json")
	opts := []build.Option{build.WithConfig(config, []string{})}
	require.NoError(t, cli.LockCmd(t.Context(), lockfile, types.ParseArchitectures(archs), withIsolatedDirs(t, opts...)))
	return lockfile
}

// buildWithLockfile builds config for archs from lockfile into an OCI layout
// and returns the layout and SBOM directories along with the build error.
func buildWithLockfile(t *testing.T, config, lockfile string, sboms bool, archs ...string) (output, sbomPath string, err error) {
	t.Helper()

	output, sbomPath = t.TempDir(), t.TempDir()
	opts := []build.Option{
		build.WithConfig(config, []string{}),
		build.WithLockFile(lockfile),
		build.WithTags("coverage:latest"),
	}
	if sboms {
		opts = append(opts, build.WithSBOMGenerators(spdx.New()))
	}

	err = cli.BuildCmd(t.Context(), "coverage:latest", output, types.ParseArchitectures(archs), []string{}, sboms, sbomPath, withIsolatedDirs(t, opts...)...)
	return output, sbomPath, err
}

// uncoveredError is the diagnostic for an amd64-only lock file that is asked
// for arm64.
func uncoveredError(lockfile string) string {
	return fmt.Sprintf("lockfile %q does not cover requested architecture arm64 (aarch64): "+
		"it was generated for amd64 (x86_64); regenerate it with `apko lock --arch=amd64,arm64`", lockfile)
}

// A lock file only pins the architectures it was generated for. Requesting any
// other architecture used to drop it from the image index without a word: the
// build exited 0 with an index (and SBOMs) describing only the architectures
// that happened to be locked, or with no manifests at all.
func TestBuildLockfileArchitectureCoverage(t *testing.T) {
	unsetSourceDateEpoch(t)

	config := filepath.Join("testdata", "apko.yaml")

	tests := []struct {
		name      string
		locked    []string
		requested []string
		sboms     bool
		// The platforms of the built index, or none when the build must fail
		// because the lock file does not cover the request.
		want []string
	}{{
		name:      "lock covers the request",
		locked:    []string{"amd64"},
		requested: []string{"amd64"},
		sboms:     true,
		want:      []string{"linux/amd64"},
	}, {
		name:      "lock covers more than the request",
		locked:    []string{"amd64", "arm64"},
		requested: []string{"arm64"},
		sboms:     true,
		want:      []string{"linux/arm64"},
	}, {
		name:      "lock covers part of the request",
		locked:    []string{"amd64"},
		requested: []string{"amd64", "arm64"},
		sboms:     true,
	}, {
		name:      "lock covers part of the request, without sboms",
		locked:    []string{"amd64"},
		requested: []string{"amd64", "arm64"},
	}, {
		// The config asks for x86_64 and aarch64.
		name:   "lock covers part of the architectures of the config",
		locked: []string{"amd64"},
		sboms:  true,
	}, {
		name:      "lock covers none of the request",
		locked:    []string{"amd64"},
		requested: []string{"arm64"},
		sboms:     true,
	}, {
		name:      "lock covers none of the request, without sboms",
		locked:    []string{"amd64"},
		requested: []string{"arm64"},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lockfile := lockConfig(t, config, tt.locked...)

			output, sbomPath, err := buildWithLockfile(t, config, lockfile, tt.sboms, tt.requested...)

			if len(tt.want) == 0 {
				require.EqualError(t, err, "locking config: "+uncoveredError(lockfile))

				// The request is rejected before anything is built: no
				// incomplete index or SBOM is left behind.
				require.Empty(t, dirEntries(t, output))
				require.Empty(t, dirEntries(t, sbomPath))
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, indexPlatforms(t, output))
		})
	}
}

// A build that names no architectures, on the command line or in the config,
// defaults to every architecture apko supports. No lock file covers more than
// it was generated for, so from a lock file the default is what it covers.
func TestBuildLockfileDefaultArchitectures(t *testing.T) {
	unsetSourceDateEpoch(t)

	config := filepath.Join(t.TempDir(), "apko.yaml")
	require.NoError(t, os.WriteFile(config, []byte(`contents:
  keyring:
    - ./testdata/melange.rsa.pub
  repositories:
    - ./testdata/packages
  packages:
    - replayout
`), 0o600))
	lockfile := lockConfig(t, config, "amd64", "arm64")

	output, _, err := buildWithLockfile(t, config, lockfile, true)
	require.NoError(t, err)
	require.Equal(t, []string{"linux/amd64", "linux/arm64"}, indexPlatforms(t, output))

	// Asking for more than the lock file covers is still an error.
	_, _, err = buildWithLockfile(t, config, lockfile, true, "amd64", "s390x")
	require.EqualError(t, err, fmt.Sprintf("locking config: lockfile %q does not cover requested architecture s390x: "+
		"it was generated for amd64 (x86_64), arm64 (aarch64); regenerate it with `apko lock --arch=amd64,arm64,s390x`", lockfile))
}

// Not every locked architecture has locked packages. These configurations
// resolve to nothing to install, and building them from a lock file has to
// keep working: the lock file still records, through its repositories, which
// architectures it was generated for.
func TestBuildLockfileWithoutLockedPackages(t *testing.T) {
	unsetSourceDateEpoch(t)

	tests := []struct {
		name   string
		config string
	}{{
		name: "empty package list",
		config: `contents:
  keyring:
    - ./testdata/melange.rsa.pub
  repositories:
    - ./testdata/packages
`,
	}, {
		name: "base image only",
		config: `contents:
  baseimage:
    image: ./testdata/base_image/
    apkindex: ./testdata/base_image/metadata/
  keyring:
    - ./testdata/melange.rsa.pub
  repositories:
    - ./testdata/packages
`,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := filepath.Join(t.TempDir(), "apko.yaml")
			require.NoError(t, os.WriteFile(config, []byte(tt.config), 0o600))

			t.Run("covered", func(t *testing.T) {
				lockfile := lockConfig(t, config, "amd64", "arm64")

				_, _, err := buildWithLockfile(t, config, lockfile, false, "amd64", "arm64")
				require.NoError(t, err)

				_, _, err = buildWithLockfile(t, config, lockfile, false, "arm64")
				require.NoError(t, err)
			})

			t.Run("not covered", func(t *testing.T) {
				lockfile := lockConfig(t, config, "amd64")

				_, _, err := buildWithLockfile(t, config, lockfile, false, "amd64", "arm64")
				require.EqualError(t, err, "locking config: "+uncoveredError(lockfile))
			})
		})
	}
}

// `apko publish` builds through the same path as `apko build`, so it must not
// push an index that is missing a requested architecture either.
func TestPublishLockfileArchitectureCoverage(t *testing.T) {
	unsetSourceDateEpoch(t)

	s := httptest.NewServer(registry.New())
	defer s.Close()
	u, err := url.Parse(s.URL)
	require.NoError(t, err)

	dst := fmt.Sprintf("%s/test/publish", u.Host)
	config := filepath.Join("testdata", "apko.yaml")
	lockfile := lockConfig(t, config, "amd64")

	archs := types.ParseArchitectures([]string{"amd64", "arm64"})
	opts := []build.Option{
		build.WithConfig(config, []string{}),
		build.WithLockFile(lockfile),
		build.WithTags(dst),
		build.WithSBOMGenerators(spdx.New()),
	}

	err = cli.PublishCmd(t.Context(), "", archs, nil, t.TempDir(), withIsolatedDirs(t, opts...), []cli.PublishOption{cli.WithTags(dst)})
	require.EqualError(t, err, "failed to build image components: locking config: "+uncoveredError(lockfile))

	// Nothing was pushed.
	ref, err := name.ParseReference(dst)
	require.NoError(t, err)
	_, err = remote.Head(ref)
	require.Error(t, err)
}

// indexPlatforms returns the platforms of the image index in the OCI layout at
// path, in manifest order.
func indexPlatforms(t *testing.T, path string) []string {
	t.Helper()

	idx, err := layout.ImageIndexFromPath(path)
	require.NoError(t, err)
	manifest, err := idx.IndexManifest()
	require.NoError(t, err)

	platforms := make([]string, 0, len(manifest.Manifests))
	for _, desc := range manifest.Manifests {
		require.NotNil(t, desc.Platform)
		platforms = append(platforms, desc.Platform.String())
	}
	return platforms
}

func dirEntries(t *testing.T, path string) []string {
	t.Helper()

	entries, err := os.ReadDir(path)
	require.NoError(t, err)

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}
