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
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/options"
)

const testOfflineRepo = "https://packages.wolfi.dev/os"

// offlineCtx builds a Context wired for an offline build from dir.
func offlineCtx(dir string, pkgs []string, repos ...string) *Context {
	if len(repos) == 0 {
		repos = []string{testOfflineRepo}
	}
	return &Context{
		ic: types.ImageConfiguration{
			Contents: types.ImageContents{
				Repositories: repos,
				Packages:     pkgs,
			},
		},
		o: options.Options{
			Arch:            types.ParseArchitecture("x86_64"),
			Offline:         true,
			OfflineCacheDir: dir,
		},
	}
}

// seedOfflineAPK writes a stand-in apk and its checksum sidecar where an offline
// build will look for it. The bytes are never expanded by these tests, which stop
// at locating the package.
func seedOfflineAPK(t *testing.T, dir, repo, name, version, checksum string) string {
	t.Helper()
	path, err := apk.OfflineCachePath(dir, apk.APKURL(repo, "x86_64", name, version))
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte("not-a-real-apk"), 0o644))
	if checksum != "" {
		require.NoError(t, os.WriteFile(apk.OfflineChecksumPath(path), []byte(checksum+"\n"), 0o644))
	}
	return path
}

func TestOfflineOnly(t *testing.T) {
	dir := t.TempDir()

	// --offline alone keeps its older meaning and must not select the index-free path.
	bc := offlineCtx(dir, nil)
	bc.o.OfflineCacheDir = ""
	require.False(t, bc.offlineOnly())

	// --offline-cache alone only populates.
	bc = offlineCtx(dir, nil)
	bc.o.Offline = false
	require.False(t, bc.offlineOnly())

	require.True(t, offlineCtx(dir, nil).offlineOnly())
}

func TestOfflineRepositories(t *testing.T) {
	t.Run("configured order is preserved and duplicates dropped", func(t *testing.T) {
		bc := offlineCtx(t.TempDir(), nil)
		bc.ic.Contents.BuildRepositories = []string{"https://b.example.com/os"}
		bc.ic.Contents.Repositories = []string{"https://a.example.com/os", "https://b.example.com/os/"}
		bc.o.ExtraRepos = []string{"https://c.example.com/os"}

		repos, err := bc.offlineRepositories()
		require.NoError(t, err)
		require.Equal(t, []string{
			"https://b.example.com/os",
			"https://a.example.com/os",
			"https://c.example.com/os",
		}, repos)
	})

	t.Run("runtime-only repositories are excluded", func(t *testing.T) {
		bc := offlineCtx(t.TempDir(), nil)
		bc.ic.Contents.RuntimeOnlyRepositories = []string{"https://runtime.example.com/os"}
		repos, err := bc.offlineRepositories()
		require.NoError(t, err)
		require.Equal(t, []string{testOfflineRepo}, repos)
	})

	t.Run("local repositories are rejected", func(t *testing.T) {
		bc := offlineCtx(t.TempDir(), nil, "/var/packages")
		_, err := bc.offlineRepositories()
		require.ErrorContains(t, err, "local repository")
	})

	t.Run("no repositories", func(t *testing.T) {
		bc := offlineCtx(t.TempDir(), nil)
		bc.ic.Contents.Repositories = nil
		_, err := bc.offlineRepositories()
		require.ErrorContains(t, err, "no repositories")
	})
}

func TestOfflineInstallablePackagesRequiresExactPins(t *testing.T) {
	dir := t.TempDir()
	bc := offlineCtx(dir, []string{
		"busybox",           // name only
		"glibc>2.0",         // range
		"libgcc~16.1",       // tilde
		"openssl@edge",      // repository pin
		"so:libc.so.6=2.43", // virtual
		"wolfi-base=1.0-r0", // fine
	})

	_, err := bc.offlineInstallablePackages(context.Background())
	require.Error(t, err)
	// Every offender is reported at once, so one run tells you the whole story.
	for _, want := range []string{"busybox", "glibc>2.0", "libgcc~16.1", "openssl@edge", "so:libc.so.6"} {
		require.ErrorContains(t, err, want)
	}
	require.NotContains(t, err.Error(), "wolfi-base=1.0-r0")
}

func TestOfflineInstallablePackagesPreservesOrder(t *testing.T) {
	dir := t.TempDir()

	// Deliberately not in sorted order: this is the order they get installed in,
	// which decides which package wins when two write the same path.
	order := []string{"wolfi-baselayout=20230201-r29", "libgcc=16.1.0-r4", "busybox=1.37.0-r61"}
	for i, spec := range order {
		name, version, _ := splitSpec(spec)
		seedOfflineAPK(t, dir, testOfflineRepo, name, version, "Q1seed"+string(rune('a'+i)))
	}

	bc := offlineCtx(dir, order)
	pkgs, err := bc.offlineInstallablePackages(context.Background())
	require.NoError(t, err)

	got := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		got = append(got, p.PackageName())
	}
	require.Equal(t, []string{"wolfi-baselayout", "libgcc", "busybox"}, got)

	// The recorded checksum, not a hash of the file, is what gets installed against.
	require.Equal(t, "Q1seeda", pkgs[0].ChecksumString())
}

func TestOfflineInstallablePackagesFirstRepositoryWins(t *testing.T) {
	dir := t.TempDir()
	const first, second = "https://first.example.com/os", "https://second.example.com/os"

	seedOfflineAPK(t, dir, first, "busybox", "1.37.0-r61", "Q1first")
	seedOfflineAPK(t, dir, second, "busybox", "1.37.0-r61", "Q1second")

	bc := offlineCtx(dir, []string{"busybox=1.37.0-r61"}, first, second)
	pkgs, err := bc.offlineInstallablePackages(context.Background())
	require.NoError(t, err)
	require.Len(t, pkgs, 1)
	require.Equal(t, "Q1first", pkgs[0].ChecksumString())
	require.Contains(t, pkgs[0].URL(), "first.example.com")

	// With the order flipped, the other one wins.
	bc = offlineCtx(dir, []string{"busybox=1.37.0-r61"}, second, first)
	pkgs, err = bc.offlineInstallablePackages(context.Background())
	require.NoError(t, err)
	require.Equal(t, "Q1second", pkgs[0].ChecksumString())
}

func TestOfflineInstallablePackagesMissing(t *testing.T) {
	dir := t.TempDir()
	seedOfflineAPK(t, dir, testOfflineRepo, "busybox", "1.37.0-r61", "Q1seed")

	t.Run("apk absent", func(t *testing.T) {
		bc := offlineCtx(dir, []string{"busybox=1.37.0-r61", "glibc=2.43-r11"})
		_, err := bc.offlineInstallablePackages(context.Background())
		require.ErrorContains(t, err, "glibc-2.43-r11: not in the cache")
		// The path it looked in is named, so the fix is obvious.
		require.ErrorContains(t, err, filepath.Join("packages.wolfi.dev", "os", "x86_64", "glibc-2.43-r11.apk"))
	})

	t.Run("wrong arch", func(t *testing.T) {
		bc := offlineCtx(dir, []string{"busybox=1.37.0-r61"})
		bc.o.Arch = types.ParseArchitecture("aarch64")
		_, err := bc.offlineInstallablePackages(context.Background())
		require.ErrorContains(t, err, "not in the cache")
	})

	t.Run("apk present but no recorded checksum", func(t *testing.T) {
		unrecorded := t.TempDir()
		seedOfflineAPK(t, unrecorded, testOfflineRepo, "busybox", "1.37.0-r61", "")

		bc := offlineCtx(unrecorded, []string{"busybox=1.37.0-r61"})
		_, err := bc.offlineInstallablePackages(context.Background())
		require.ErrorContains(t, err, "no recorded checksum")
	})

	t.Run("cache directory does not exist", func(t *testing.T) {
		bc := offlineCtx(filepath.Join(t.TempDir(), "nope"), []string{"busybox=1.37.0-r61"})
		_, err := bc.offlineInstallablePackages(context.Background())
		require.ErrorIs(t, err, os.ErrNotExist)
	})
}

func TestOfflineKeyring(t *testing.T) {
	dir := t.TempDir()
	keysDir := filepath.Join(dir, offlineKeysDir)
	require.NoError(t, os.MkdirAll(keysDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(keysDir, "wolfi-signing.rsa.pub"), []byte("key"), 0o644))

	bc := offlineCtx(dir, nil)

	t.Run("remote keys are redirected to the cache", func(t *testing.T) {
		got, err := bc.offlineKeyring([]string{"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"})
		require.NoError(t, err)
		require.Equal(t, []string{filepath.Join(keysDir, "wolfi-signing.rsa.pub")}, got)
	})

	t.Run("local keys are left alone", func(t *testing.T) {
		got, err := bc.offlineKeyring([]string{"/etc/apk/keys/local.rsa.pub"})
		require.NoError(t, err)
		require.Equal(t, []string{"/etc/apk/keys/local.rsa.pub"}, got)
	})

	t.Run("missing key is an error naming where it was expected", func(t *testing.T) {
		_, err := bc.offlineKeyring([]string{"https://packages.wolfi.dev/os/other-signing.rsa.pub"})
		require.ErrorContains(t, err, "other-signing.rsa.pub")
		require.ErrorContains(t, err, keysDir)
	})
}

// splitSpec splits "name=version" for test setup.
func splitSpec(spec string) (name, version string, ok bool) {
	c := apk.ResolvePackageNameVersionPin(spec)
	return c.Name, c.Version, c.IsExactVersion()
}

func TestValidateOffline(t *testing.T) {
	dir := t.TempDir()

	// A lockfile and an offline cache are two ways to pin the same thing, so
	// silently honouring one and ignoring the other would be misleading.
	bc := offlineCtx(dir, nil)
	bc.o.Lockfile = "apko.lock.json"
	require.ErrorContains(t, validateOffline(&bc.o), "two ways to pin")

	// A lockfile with only a populating offline cache is fine.
	bc = offlineCtx(dir, nil)
	bc.o.Offline = false
	bc.o.Lockfile = "apko.lock.json"
	require.NoError(t, validateOffline(&bc.o))

	require.NoError(t, validateOffline(&offlineCtx(dir, nil).o))
}
