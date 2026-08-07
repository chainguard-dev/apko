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

package apk

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/apk/auth"
)

func TestOfflineCachePath(t *testing.T) {
	root := filepath.Join("/tmp", "oc")

	for _, tc := range []struct {
		name    string
		url     string
		want    string
		wantErr bool
	}{{
		name: "https package",
		url:  "https://packages.wolfi.dev/os/x86_64/busybox-1.37.0-r61.apk",
		want: filepath.Join(root, "packages.wolfi.dev", "os", "x86_64", "busybox-1.37.0-r61.apk"),
	}, {
		name: "http package",
		url:  "http://example.com/main/aarch64/foo-1.0-r0.apk",
		want: filepath.Join(root, "example.com", "main", "aarch64", "foo-1.0-r0.apk"),
	}, {
		name: "host with port is kept distinct",
		url:  "https://example.com:8443/main/x86_64/foo-1.0-r0.apk",
		want: filepath.Join(root, "example.com:8443", "main", "x86_64", "foo-1.0-r0.apk"),
	}, {
		// The query string is not part of the package's identity, and including
		// it would make the same apk cache to two different paths.
		name: "query string is ignored",
		url:  "https://example.com/main/x86_64/foo-1.0-r0.apk?token=abc",
		want: filepath.Join(root, "example.com", "main", "x86_64", "foo-1.0-r0.apk"),
	}, {
		name:    "literal traversal in path",
		url:     "https://example.com/../../../etc/passwd.apk",
		wantErr: true,
	}, {
		// url.Parse decodes %2e and %2f, so traversal can arrive already hidden.
		name:    "percent-encoded traversal in path",
		url:     "https://example.com/a/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd.apk",
		wantErr: true,
	}, {
		name:    "traversal in host",
		url:     "https://../../../etc/x86_64/foo-1.0-r0.apk",
		wantErr: true,
	}, {
		name:    "file scheme is not cacheable",
		url:     "file:///var/packages/x86_64/foo-1.0-r0.apk",
		wantErr: true,
	}, {
		name:    "bare path is not cacheable",
		url:     "/var/packages/x86_64/foo-1.0-r0.apk",
		wantErr: true,
	}, {
		name:    "no host",
		url:     "https:///main/x86_64/foo-1.0-r0.apk",
		wantErr: true,
	}, {
		name:    "not an apk",
		url:     "https://example.com/main/x86_64/APKINDEX.tar.gz",
		wantErr: true,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := OfflineCachePath(root, tc.url)
			if tc.wantErr {
				require.Error(t, err)
				require.Empty(t, got)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestOfflineCachePathEmptyDir(t *testing.T) {
	_, err := OfflineCachePath("", "https://example.com/main/x86_64/foo-1.0-r0.apk")
	require.Error(t, err)
}

func TestAPKURL(t *testing.T) {
	// Must agree with RepositoryPackage.URL(), or a package located offline would
	// not be found at the path a populating run wrote it to.
	repo := Repository{URI: "https://example.com/main/x86_64"}
	pkg := NewRepositoryPackage(&testPkg, repo.WithIndex(&APKIndex{Packages: []*Package{&testPkg}}))
	require.Equal(t, pkg.URL(), APKURL("https://example.com/main", "x86_64", testPkg.Name, testPkg.Version))
}

func TestIsRemoteURL(t *testing.T) {
	require.True(t, IsRemoteURL("https://example.com/main"))
	require.True(t, IsRemoteURL("http://example.com/main"))
	require.False(t, IsRemoteURL("/var/packages"))
	require.False(t, IsRemoteURL("file:///var/packages"))
}

func TestOfflineChecksumRoundTrip(t *testing.T) {
	dir := t.TempDir()
	apkPath := filepath.Join(dir, "foo-1.0-r0.apk")

	_, err := ReadOfflineChecksum(apkPath)
	require.ErrorIs(t, err, os.ErrNotExist)

	require.NoError(t, writeOfflineChecksum(apkPath, "Q1abcdef"))
	got, err := ReadOfflineChecksum(apkPath)
	require.NoError(t, err)
	require.Equal(t, "Q1abcdef", got)

	// Overwriting an existing record must work, since a populating run rewrites
	// the sidecar whenever it does not match the index.
	require.NoError(t, writeOfflineChecksum(apkPath, "Q1123456"))
	got, err = ReadOfflineChecksum(apkPath)
	require.NoError(t, err)
	require.Equal(t, "Q1123456", got)

	require.Equal(t, apkPath+".Q1", OfflineChecksumPath(apkPath))
}

func TestReadOfflineChecksumRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	apkPath := filepath.Join(dir, "foo-1.0-r0.apk")
	require.NoError(t, os.WriteFile(OfflineChecksumPath(apkPath), []byte("not-a-checksum\n"), 0o644))

	_, err := ReadOfflineChecksum(apkPath)
	require.ErrorContains(t, err, "expected a Q1-prefixed checksum")
}

// offlineGetter builds a package getter that mirrors into offlineDir and serves
// packages from local testdata.
func offlineGetter(t *testing.T, offlineDir string, tr http.RoundTripper) *defaultPackageGetter {
	t.Helper()
	return newDefaultPackageGetter(&http.Client{Transport: tr}, &cache{
		dir:    t.TempDir(),
		shared: NewCache(false),
	}, auth.DefaultAuthenticators, withOfflineCacheDir(offlineDir))
}

func TestOfflineCachePopulate(t *testing.T) {
	var (
		ctx      = context.Background()
		repo     = Repository{URI: testAlpineRepos + "/" + testArch}
		pkg      = NewRepositoryPackage(&testPkg, repo.WithIndex(&APKIndex{Packages: []*Package{&testPkg}}))
		offline  = t.TempDir()
		wantPath = filepath.Join(offline, "dl-cdn.alpinelinux.org", "alpine", "v3.16", "main", testArch, testPkgFilename)
	)

	d := offlineGetter(t, offline, &testLocalTransport{root: testPrimaryPkgDir, basenameOnly: true})
	exp, err := d.GetPackage(ctx, pkg)
	require.NoError(t, err)
	require.NoError(t, exp.Close())

	// The raw apk lands in the mirror, alongside the index's checksum for it.
	require.FileExists(t, wantPath)
	chk, err := ReadOfflineChecksum(wantPath)
	require.NoError(t, err)
	require.Equal(t, pkg.ChecksumString(), chk)

	// Nothing is left behind at a temporary name.
	entries, err := os.ReadDir(filepath.Dir(wantPath))
	require.NoError(t, err)
	require.Len(t, entries, 2, "expected only the apk and its sidecar, got %v", entries)
}

func TestOfflineCacheServesWithoutNetwork(t *testing.T) {
	var (
		ctx     = context.Background()
		repo    = Repository{URI: testAlpineRepos + "/" + testArch}
		pkg     = NewRepositoryPackage(&testPkg, repo.WithIndex(&APKIndex{Packages: []*Package{&testPkg}}))
		offline = t.TempDir()
	)

	// Populate with the network available.
	d := offlineGetter(t, offline, &testLocalTransport{root: testPrimaryPkgDir, basenameOnly: true})
	exp, err := d.GetPackage(ctx, pkg)
	require.NoError(t, err)
	require.NoError(t, exp.Close())

	// A second getter whose transport always fails must still succeed, proving the
	// apk came from the mirror rather than the network. A fresh --cache-dir is used
	// so the expanded cache cannot be the source either.
	d2 := offlineGetter(t, offline, &testLocalTransport{fail: true})
	exp2, err := d2.GetPackage(ctx, pkg)
	require.NoError(t, err)
	require.NoError(t, exp2.Close())
}

func TestOfflineCacheDetectsDifferentContentSameName(t *testing.T) {
	var (
		ctx     = context.Background()
		repo    = Repository{URI: testAlpineRepos + "/" + testArch}
		index   = &APKIndex{Packages: []*Package{&testPkg}}
		pkg     = NewRepositoryPackage(&testPkg, repo.WithIndex(index))
		offline = t.TempDir()
	)

	d := offlineGetter(t, offline, &testLocalTransport{root: testPrimaryPkgDir, basenameOnly: true})
	exp, err := d.GetPackage(ctx, pkg)
	require.NoError(t, err)
	require.NoError(t, exp.Close())

	// Stand in for a repository that republished different content under the same
	// name and version: the index now reports a checksum the cached apk does not
	// have. Naming it separately from the fetch would let a stale apk pass, so the
	// cached bytes must be re-checked on every run.
	republished := testPkg
	republished.Checksum = append([]byte(nil), testPkg.Checksum...)
	republished.Checksum[0]++
	changed := NewRepositoryPackage(&republished, repo.WithIndex(index))

	// Forget the in-process entry, which is keyed by URL and would answer first.
	globalApkCache.Forget(changed.URL())

	d2 := offlineGetter(t, offline, &testLocalTransport{root: testPrimaryPkgDir, basenameOnly: true})
	_, err = d2.GetPackage(ctx, changed)
	require.Error(t, err)
	require.ErrorContains(t, err, "control hash mismatch")
	require.ErrorContains(t, err, "offline cache")
}

func TestOfflineCacheRecordsChecksumForHandPlacedAPK(t *testing.T) {
	var (
		ctx     = context.Background()
		repo    = Repository{URI: testAlpineRepos + "/" + testArch}
		pkg     = NewRepositoryPackage(&testPkg, repo.WithIndex(&APKIndex{Packages: []*Package{&testPkg}}))
		offline = t.TempDir()
	)

	// An apk copied in from a mirror has no sidecar, so it cannot be used offline
	// yet. Verifying it against the index is what earns it one.
	apkPath, err := OfflineCachePath(offline, pkg.URL())
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(apkPath), 0o755))
	contents, err := os.ReadFile(filepath.Join(testPrimaryPkgDir, testPkgFilename))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(apkPath, contents, 0o644))

	_, err = ReadOfflineChecksum(apkPath)
	require.ErrorIs(t, err, os.ErrNotExist)

	// A transport that always fails, to show the apk on disk is what was used.
	d := offlineGetter(t, offline, &testLocalTransport{fail: true})
	exp, err := d.GetPackage(ctx, pkg)
	require.NoError(t, err)
	require.NoError(t, exp.Close())

	chk, err := ReadOfflineChecksum(apkPath)
	require.NoError(t, err)
	require.Equal(t, pkg.ChecksumString(), chk)
}
