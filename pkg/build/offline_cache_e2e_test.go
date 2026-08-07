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

package build_test

import (
	"crypto/sha1" //nolint:gosec // this is what apk tools is using
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/apk/apk"
	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/build/types"
)

// offlineImageConfig describes an image built from the local testdata repository
// served at repoURL.
func offlineImageConfig(repoURL string, packages ...string) types.ImageConfiguration {
	return types.ImageConfiguration{
		Contents: types.ImageContents{
			Repositories: []string{repoURL},
			Keyring:      []string{repoURL + "/melange.rsa.pub"},
			Packages:     packages,
		},
		Archs: []types.Architecture{types.ParseArchitecture("amd64")},
	}
}

// TestOfflineCacheEndToEnd populates an offline cache from a served repository,
// then rebuilds the same image with that server shut down, which proves the
// second build reads neither the index nor the network.
func TestOfflineCacheEndToEnd(t *testing.T) {
	ctx := t.Context()
	offlineDir := t.TempDir()

	srv := httptest.NewServer(http.FileServer(http.Dir("testdata/packages")))
	repoURL := srv.URL

	// Resolve the unpinned request the way the CLI does, so the reference build
	// records the same pinned package set an offline build will be given. Without
	// this the two configs genuinely differ and /etc/apko.json would too.
	configs, _, err := build.LockImageConfiguration(ctx,
		offlineImageConfig(repoURL, "pretend-baselayout", "replayout", "custom-ca-certs-1"),
		build.WithOfflineCache(offlineDir),
	)
	require.NoError(t, err)
	resolved, ok := configs["amd64"]
	require.True(t, ok, "expected a resolved config for amd64, got %v", configs)

	// The reference build, which resolves and populates the cache as it goes.
	bc, err := build.New(ctx, apkfs.NewMemFS(),
		build.WithImageConfiguration(*resolved),
		build.WithArch(types.ParseArchitecture("amd64")),
		build.WithOfflineCache(offlineDir),
	)
	require.NoError(t, err)

	_, onlineLayer, err := bc.BuildLayer(ctx)
	require.NoError(t, err)
	onlineDiffID, err := onlineLayer.DiffID()
	require.NoError(t, err)

	// InstalledPackages reports them in the order they were installed, which is the
	// order an offline build has to be given to reproduce this image.
	installed, err := bc.InstalledPackages()
	require.NoError(t, err)
	require.NotEmpty(t, installed)

	// Every installed package is mirrored, with its checksum recorded, and the
	// signing key is copied in so the cache stands alone.
	host, err := url.Parse(repoURL)
	require.NoError(t, err)
	pinned := make([]string, 0, len(installed))
	for _, p := range installed {
		apkPath := filepath.Join(offlineDir, host.Host, "x86_64", p.Name+"-"+p.Version+".apk")
		require.FileExists(t, apkPath)

		chk, err := apk.ReadOfflineChecksum(apkPath)
		require.NoError(t, err)
		require.Equal(t, p.ChecksumString(), chk, "recorded checksum should be the one the index reported")

		pinned = append(pinned, p.Name+"="+p.Version)
	}
	require.FileExists(t, filepath.Join(offlineDir, "keys", "melange.rsa.pub"))

	// Take the network away entirely. The URLs in the config stay the same, so the
	// only way the next build can succeed is from the offline cache.
	srv.Close()

	t.Run("resolution is skipped", func(t *testing.T) {
		// Would need the index, which is now unreachable.
		_, _, err := build.LockImageConfiguration(ctx, offlineImageConfig(repoURL, pinned...),
			build.WithOffline(true),
			build.WithOfflineCache(offlineDir),
		)
		require.NoError(t, err)
	})

	t.Run("image is byte-identical to the resolved build", func(t *testing.T) {
		obc, err := build.New(ctx, apkfs.NewMemFS(),
			build.WithImageConfiguration(offlineImageConfig(repoURL, pinned...)),
			build.WithArch(types.ParseArchitecture("amd64")),
			build.WithOffline(true),
			build.WithOfflineCache(offlineDir),
		)
		require.NoError(t, err)

		_, offlineLayer, err := obc.BuildLayer(ctx)
		require.NoError(t, err)
		offlineDiffID, err := offlineLayer.DiffID()
		require.NoError(t, err)

		// The whole point: given the same closure in install order, an offline build
		// reproduces the resolved build exactly, down to the layer bytes. This
		// fixture's install order happens to match sorted order, so the sibling
		// subtest below is what covers the two being handled differently.
		require.Equal(t, onlineDiffID, offlineDiffID)

		offlineInstalled, err := obc.InstalledPackages()
		require.NoError(t, err)
		require.Len(t, offlineInstalled, len(installed))
		for i := range installed {
			require.Equal(t, installed[i].Name, offlineInstalled[i].Name)
			require.Equal(t, installed[i].Version, offlineInstalled[i].Version)
		}
	})

	t.Run("recorded config is sorted while install order is as given", func(t *testing.T) {
		// Deliberately not in sorted order. /etc/apko.json must still record the
		// sorted set, matching what a resolving build records, or the two builds
		// would differ in that one file. The install order must follow the config.
		reversed := slices.Clone(pinned)
		slices.Reverse(reversed)
		sorted := slices.Sorted(slices.Values(pinned))
		require.NotEqual(t, sorted, reversed, "fixture cannot distinguish sorted from configured order")

		memfs := apkfs.NewMemFS()
		obc, err := build.New(ctx, memfs,
			build.WithImageConfiguration(offlineImageConfig(repoURL, reversed...)),
			build.WithArch(types.ParseArchitecture("amd64")),
			build.WithOffline(true),
			build.WithOfflineCache(offlineDir),
		)
		require.NoError(t, err)
		require.NoError(t, obc.BuildImage(ctx))

		b, err := fs.ReadFile(memfs, "etc/apko.json")
		require.NoError(t, err)
		var recorded types.ImageConfiguration
		require.NoError(t, json.Unmarshal(b, &recorded))
		require.Equal(t, sorted, recorded.Contents.Packages)

		// Installed in the order the config listed them, not the recorded order.
		installedNames := make([]string, 0, len(reversed))
		offlineInstalled, err := obc.InstalledPackages()
		require.NoError(t, err)
		for _, p := range offlineInstalled {
			installedNames = append(installedNames, p.Name+"="+p.Version)
		}
		require.Equal(t, reversed, installedNames)
	})

	t.Run("unpinned package is refused", func(t *testing.T) {
		obc, err := build.New(ctx, apkfs.NewMemFS(),
			build.WithImageConfiguration(offlineImageConfig(repoURL, "pretend-baselayout")),
			build.WithArch(types.ParseArchitecture("amd64")),
			build.WithOffline(true),
			build.WithOfflineCache(offlineDir),
		)
		require.NoError(t, err)

		err = obc.BuildImage(ctx)
		require.ErrorContains(t, err, "pinned to an exact version")
	})

	t.Run("package missing from the cache is refused", func(t *testing.T) {
		obc, err := build.New(ctx, apkfs.NewMemFS(),
			build.WithImageConfiguration(offlineImageConfig(repoURL, "no-such-package=1.0.0-r0")),
			build.WithArch(types.ParseArchitecture("amd64")),
			build.WithOffline(true),
			build.WithOfflineCache(offlineDir),
		)
		require.NoError(t, err)

		err = obc.BuildImage(ctx)
		require.ErrorContains(t, err, "not in the cache")
	})

	t.Run("apk whose recorded checksum was tampered with is refused", func(t *testing.T) {
		// Copy the cache so the tampering does not affect the other subtests.
		tampered := t.TempDir()
		require.NoError(t, os.CopyFS(tampered, os.DirFS(offlineDir)))

		apkPath := filepath.Join(tampered, host.Host, "x86_64", installed[0].Name+"-"+installed[0].Version+".apk")
		// A well-formed but wrong checksum: the base64 of an all-zero SHA-1.
		wrong := "Q1" + base64.StdEncoding.EncodeToString(make([]byte, sha1.Size))
		require.NoError(t, os.WriteFile(apk.OfflineChecksumPath(apkPath), []byte(wrong+"\n"), 0o644))

		obc, err := build.New(ctx, apkfs.NewMemFS(),
			build.WithImageConfiguration(offlineImageConfig(repoURL, pinned...)),
			build.WithArch(types.ParseArchitecture("amd64")),
			build.WithOffline(true),
			build.WithOfflineCache(tampered),
		)
		require.NoError(t, err)

		err = obc.BuildImage(ctx)
		require.ErrorContains(t, err, "control hash mismatch")
	})
}
