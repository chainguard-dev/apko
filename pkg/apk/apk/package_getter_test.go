package apk

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/apk/auth"
)

func TestFetchPackage(t *testing.T) {
	var (
		repo          = Repository{URI: fmt.Sprintf("%s/%s", testAlpineRepos, testArch)}
		packages      = []*Package{&testPkg}
		repoWithIndex = repo.WithIndex(&APKIndex{
			Packages: packages,
		})
		testEtag = "testetag"
		pkg      = NewRepositoryPackage(&testPkg, repoWithIndex)
		ctx      = context.Background()
	)
	prepGetter := func(t *testing.T, tr http.RoundTripper, cacheDir string) *defaultPackageGetter {
		// set a client so we use local testdata instead of heading out to the Internet each time
		path, err := filepath.Abs(cacheDir)
		require.NoErrorf(t, err, "unable to get absolute path for cache dir")
		httpClient := &http.Client{Transport: tr}
		return newDefaultPackageGetter(httpClient, &cache{
			dir:     path,
			offline: false,
			shared:  NewCache(false),
		}, auth.DefaultAuthenticators)
	}
	t.Run("no cache", func(t *testing.T) {
		a := prepGetter(t, &testLocalTransport{root: testPrimaryPkgDir, basenameOnly: true}, "")
		_, err := a.fetchPackage(ctx, pkg)
		require.NoErrorf(t, err, "unable to install package")
	})
	t.Run("cache miss no network", func(t *testing.T) {
		// we use a transport that always returns a 404 so we know we're not hitting the network
		// it should fail for a cache hit
		tmpDir := t.TempDir()
		a := prepGetter(t, &testLocalTransport{fail: true}, tmpDir)
		_, err := a.fetchPackage(ctx, pkg)
		require.Error(t, err, "should fail when no cache and no network")
	})
	t.Run("cache miss network should fill cache", func(t *testing.T) {
		tmpDir := t.TempDir()
		a := prepGetter(t, &testLocalTransport{root: testPrimaryPkgDir, basenameOnly: true}, tmpDir)
		// fill the cache
		repoDir := filepath.Join(tmpDir, url.QueryEscape(testAlpineRepos), testArch)
		err := os.MkdirAll(repoDir, 0o755)
		require.NoError(t, err, "unable to mkdir cache")

		cacheApkFile := filepath.Join(repoDir, testPkgFilename)
		cacheApkDir := strings.TrimSuffix(cacheApkFile, ".apk")

		_, err = a.GetPackage(ctx, pkg)
		require.NoErrorf(t, err, "unable to install pkg")
		// check that the package file is in place
		_, err = os.Stat(cacheApkDir)
		require.NoError(t, err, "apk file not found in cache")
		// check that the contents are the same
		exp, err := a.cachedPackage(ctx, pkg, cacheApkDir)
		if err != nil {
			t.Logf("did not find cachedPackage(%q) in %s: %v", pkg.Name, cacheApkDir, err)
			files, err := os.ReadDir(cacheApkDir)
			require.NoError(t, err, "listing "+cacheApkDir)
			for _, f := range files {
				t.Logf("  found %q", f.Name())
			}
		}
		require.NoError(t, err, "unable to read cache apk file")
		f, err := exp.APK()
		require.NoError(t, err, "unable to read cached files as apk")
		defer f.Close()

		apk1, err := io.ReadAll(f)
		require.NoError(t, err, "unable to read cached apk bytes")

		apk2, err := os.ReadFile(filepath.Join(testPrimaryPkgDir, testPkgFilename))
		require.NoError(t, err, "unable to read previous apk file")
		require.Equal(t, apk1, apk2, "apk files do not match")
	})
	t.Run("handle missing cache files when expanding APK", func(t *testing.T) {
		tmpDir := t.TempDir()
		a := prepGetter(t, http.DefaultTransport, tmpDir)

		// Fill the cache
		exp, err := a.GetPackage(ctx, pkg)
		require.NoError(t, err, "unable to expand package")
		_, err = os.Stat(exp.TarFile)
		require.NoError(t, err, "unable to stat cached tar file")

		// Delete the tar file from the cache
		require.NoError(t, os.Remove(exp.TarFile), "unable to delete cached tar file")
		_, err = os.Stat(exp.TarFile)
		require.ErrorIs(t, err, os.ErrNotExist, "unexpectedly able to stat cached tar file that should have been deleted")

		// Expand the package again, this should re-populate the cache.
		exp2, err := a.GetPackage(ctx, pkg)
		require.NoError(t, err, "unable to expandPackage after deleting cached tar file")
		_, err = os.Stat(exp2.TarFile)
		require.NoError(t, err, "unable to stat cached tar file")

		// Delete and recreate the tar file from the cache (changing its inodes)
		bs, err := os.ReadFile(exp2.TarFile)
		require.NoError(t, err, "unable to read cached tar file")
		require.NoError(t, os.Remove(exp2.TarFile), "unable to delete cached tar file")
		require.NoError(t, os.WriteFile(exp2.TarFile, bs, 0o644), "unable to recreate cached tar file")

		// Ensure that the underlying reader is different (i.e. we re-read the file)
		exp3, err := a.GetPackage(ctx, pkg)
		require.NoError(t, err, "unable to expandPackage after deleting and recreating cached tar file")
		require.NotEqual(t, exp2.TarFS.UnderlyingReader(), exp3.TarFS.UnderlyingReader())

		// We should be able to read the APK contents
		rc, err := exp3.APK()
		require.NoError(t, err, "unable to get reader for APK()")
		_, err = io.ReadAll(rc)
		require.NoError(t, err, "unable to read APK contents")
	})
	t.Run("cache hit no etag", func(t *testing.T) {
		tmpDir := t.TempDir()
		a := prepGetter(t,
			&testLocalTransport{root: testAlternatePkgDir, basenameOnly: true, headers: map[string][]string{http.CanonicalHeaderKey("etag"): {testEtag}}},
			tmpDir)
		// fill the cache
		repoDir := filepath.Join(tmpDir, url.QueryEscape(testAlpineRepos), testArch)
		err := os.MkdirAll(repoDir, 0o755)
		require.NoError(t, err, "unable to mkdir cache")

		contents, err := os.ReadFile(filepath.Join(testPrimaryPkgDir, testPkgFilename))
		require.NoError(t, err, "unable to read apk file")
		cacheApkFile := filepath.Join(repoDir, testPkgFilename)
		err = os.WriteFile(cacheApkFile, contents, 0o644) //nolint:gosec // we're writing a test file
		require.NoError(t, err, "unable to write cache apk file")

		_, err = a.fetchPackage(ctx, pkg)
		require.NoErrorf(t, err, "unable to install pkg")
		// check that the package file is in place
		_, err = os.Stat(cacheApkFile)
		require.NoError(t, err, "apk file not found in cache")
		// check that the contents are the same as the original
		apk1, err := os.ReadFile(cacheApkFile)
		require.NoError(t, err, "unable to read cache apk file")
		require.Equal(t, apk1, contents, "apk files do not match")
	})
	t.Run("cache hit etag match", func(t *testing.T) {
		tmpDir := t.TempDir()
		a := prepGetter(t,
			&testLocalTransport{root: testAlternatePkgDir, basenameOnly: true, headers: map[string][]string{http.CanonicalHeaderKey("etag"): {testEtag}}},
			tmpDir)
		// fill the cache
		repoDir := filepath.Join(tmpDir, url.QueryEscape(testAlpineRepos), testArch)
		err := os.MkdirAll(repoDir, 0o755)
		require.NoError(t, err, "unable to mkdir cache")

		contents, err := os.ReadFile(filepath.Join(testPrimaryPkgDir, testPkgFilename))
		require.NoError(t, err, "unable to read apk file")
		cacheApkFile := filepath.Join(repoDir, testPkgFilename)
		err = os.WriteFile(cacheApkFile, contents, 0o644) //nolint:gosec // we're writing a test file
		require.NoError(t, err, "unable to write cache apk file")
		err = os.WriteFile(cacheApkFile+".etag", []byte(testEtag), 0o644) //nolint:gosec // we're writing a test file
		require.NoError(t, err, "unable to write etag")

		_, err = a.fetchPackage(ctx, pkg)
		require.NoErrorf(t, err, "unable to install pkg")
		// check that the package file is in place
		_, err = os.Stat(cacheApkFile)
		require.NoError(t, err, "apk file not found in cache")
		// check that the contents are the same as the original
		apk1, err := os.ReadFile(cacheApkFile)
		require.NoError(t, err, "unable to read cache apk file")
		require.Equal(t, apk1, contents, "apk files do not match")
	})
	t.Run("cache hit etag miss", func(t *testing.T) {
		tmpDir := t.TempDir()
		a := prepGetter(t,
			&testLocalTransport{root: testAlternatePkgDir, basenameOnly: true, headers: map[string][]string{http.CanonicalHeaderKey("etag"): {testEtag + "abcdefg"}}},
			tmpDir)
		// fill the cache
		repoDir := filepath.Join(tmpDir, url.QueryEscape(testAlpineRepos), testArch)
		err := os.MkdirAll(repoDir, 0o755)
		require.NoError(t, err, "unable to mkdir cache")

		contents, err := os.ReadFile(filepath.Join(testPrimaryPkgDir, testPkgFilename))
		require.NoError(t, err, "unable to read apk file")
		cacheApkFile := filepath.Join(repoDir, testPkgFilename)
		err = os.WriteFile(cacheApkFile, contents, 0o644) //nolint:gosec // we're writing a test file
		require.NoError(t, err, "unable to write cache apk file")
		err = os.WriteFile(cacheApkFile+".etag", []byte(testEtag), 0o644) //nolint:gosec // we're writing a test file
		require.NoError(t, err, "unable to write etag")

		_, err = a.fetchPackage(ctx, pkg)
		require.NoErrorf(t, err, "unable to install pkg")
		// check that the package file is in place
		_, err = os.Stat(cacheApkFile)
		require.NoError(t, err, "apk file not found in cache")
		// check that the contents are the same as the original
		apk1, err := os.ReadFile(cacheApkFile)
		require.NoError(t, err, "unable to read cache apk file")
		apk2, err := os.ReadFile(filepath.Join(testAlternatePkgDir, testPkgFilename))
		require.NoError(t, err, "unable to read testdata apk file")
		require.Equal(t, apk1, apk2, "apk files do not match")
	})
}

func TestAuth_good(t *testing.T) {
	called := false
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if gotuser, gotpass, ok := r.BasicAuth(); !ok || gotuser != testUser || gotpass != testPass {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		http.FileServer(http.Dir(testPrimaryPkgDir)).ServeHTTP(w, r)
	}))
	defer s.Close()
	host := strings.TrimPrefix(s.URL, "http://")

	repo := Repository{URI: s.URL}
	repoWithIndex := repo.WithIndex(&APKIndex{Packages: []*Package{&testPkg}})
	pkg := NewRepositoryPackage(&testPkg, repoWithIndex)
	ctx := context.Background()

	getter := newDefaultPackageGetter(http.DefaultClient, nil, auth.StaticAuth(host, testUser, testPass))

	_, err := getter.GetPackage(ctx, pkg)
	require.NoErrorf(t, err, "unable to expand package")
	require.True(t, called, "did not make request")
}

func TestAuth_bad(t *testing.T) {
	called := false
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if gotuser, gotpass, ok := r.BasicAuth(); !ok || gotuser != testUser || gotpass != testPass {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		http.FileServer(http.Dir(testPrimaryPkgDir)).ServeHTTP(w, r)
	}))
	defer s.Close()
	host := strings.TrimPrefix(s.URL, "http://")

	repo := Repository{URI: s.URL}
	repoWithIndex := repo.WithIndex(&APKIndex{Packages: []*Package{&testPkg}})
	pkg := NewRepositoryPackage(&testPkg, repoWithIndex)
	ctx := context.Background()

	getter := newDefaultPackageGetter(http.DefaultClient, nil, auth.StaticAuth(host, "baduser", "badpass"))

	_, err := getter.GetPackage(ctx, pkg)
	require.Error(t, err, "unable to expand package")
	require.True(t, called, "did not make request")
}
