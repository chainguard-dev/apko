package build_test

// The snippets in docs/offline-cache.md, compiled and run against the local
// testdata repository so that the documented flow cannot drift from the API.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/apk/apk"
	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/build/types"
)

func docFlow(ctx context.Context, ic types.ImageConfiguration, offlineDir, cacheDir string) error {
	// --- Reproducing a build byte for byte ---
	configs, _, err := build.LockImageConfiguration(ctx, ic,
		build.WithOfflineCache(offlineDir),
	)
	if err != nil {
		return err
	}
	resolved, ok := configs["amd64"] // keyed by types.Architecture.String(), plus "index"
	if !ok {
		return fmt.Errorf("no resolved config for amd64")
	}

	// --- Populating a cache ---
	bc, err := build.New(ctx, apkfs.NewMemFS(),
		build.WithImageConfiguration(*resolved),
		build.WithArch(types.ParseArchitecture("amd64")),
		build.WithCache(cacheDir, false, apk.NewCache(true)),
		build.WithOfflineCache(offlineDir),
	)
	if err != nil {
		return err
	}
	if _, _, err := bc.BuildLayer(ctx); err != nil {
		return err
	}

	// --- Capturing the pinned closure ---
	installed, err := bc.InstalledPackages()
	if err != nil {
		return err
	}
	pinned := make([]string, 0, len(installed))
	for _, p := range installed {
		pinned = append(pinned, p.Name+"="+p.Version)
	}

	// --- Building offline ---
	offlineIC := *resolved
	offlineIC.Contents.Packages = pinned

	obc, err := build.New(ctx, apkfs.NewMemFS(),
		build.WithImageConfiguration(offlineIC),
		build.WithArch(types.ParseArchitecture("amd64")),
		build.WithOffline(true),
		build.WithOfflineCache(offlineDir),
	)
	if err != nil {
		return err
	}
	if _, _, err := obc.BuildLayer(ctx); err != nil {
		return err
	}
	return nil
}

func docAPKLayer(offlineDir, repo, arch, name, version string) error {
	path, err := apk.OfflineCachePath(offlineDir, apk.APKURL(repo, arch, name, version))
	if err != nil {
		return err
	}
	checksum, err := apk.ReadOfflineChecksum(path)
	if err != nil {
		return err
	}
	_ = checksum
	return nil
}

func TestOfflineCacheDocumentedFlow(t *testing.T) {
	srv := httptest.NewServer(http.FileServer(http.Dir("testdata/packages")))
	defer srv.Close()

	offlineDir, cacheDir := t.TempDir(), t.TempDir()
	ic := offlineImageConfig(srv.URL, "pretend-baselayout", "replayout", "custom-ca-certs-1")

	require.NoError(t, docFlow(t.Context(), ic, offlineDir, cacheDir))
	require.NoError(t, docAPKLayer(offlineDir, srv.URL, "x86_64", "pretend-baselayout", "1.0.0-r0"))
}
