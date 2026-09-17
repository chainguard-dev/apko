package apk

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/apk/auth"
	"chainguard.dev/apko/pkg/apk/expandapk"
	"chainguard.dev/apko/pkg/apk/expandapk/tarfs"
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

		// Delete the uncompressed tar from the cache. Nothing depends on it any
		// more: the data served is inflated from the compressed section into a
		// private copy, so losing this file must not break a subsequent read.
		require.NoError(t, os.Remove(exp.TarFile), "unable to delete cached tar file")
		_, err = os.Stat(exp.TarFile)
		require.ErrorIs(t, err, os.ErrNotExist, "unexpectedly able to stat cached tar file that should have been deleted")

		exp2, err := a.GetPackage(ctx, pkg)
		require.NoError(t, err, "unable to expandPackage after deleting cached tar file")
		require.NotEmpty(t, fsNames(t, exp2.TarFS), "package contents unavailable after deleting the cached tar")

		// Deleting the compressed section is a different matter, since that is
		// what verification chains to. It must invalidate the entry and be
		// re-fetched rather than served from memory.
		require.NoError(t, os.Remove(exp2.PackageFile), "unable to delete cached package file")
		require.False(t, exp2.IsValid(), "an entry missing its compressed data section should not be reusable")

		exp3, err := a.GetPackage(ctx, pkg)
		require.NoError(t, err, "unable to expandPackage after deleting the compressed data section")
		_, err = os.Stat(exp3.PackageFile)
		require.NoError(t, err, "the compressed data section should have been re-fetched")

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

// TestGetPackage_ChecksumMismatch confirms that a package served by a repository
// that does not match the checksum recorded in the (signed) APKINDEX is rejected
// rather than silently installed. This guards against compromised mirrors or
// poisoned caches substituting package contents.
func TestGetPackage_ChecksumMismatch(t *testing.T) {
	tampered := testPkg
	// Flip one byte of the recorded checksum so the downloaded content's
	// real control-section SHA-1 will not match.
	tampered.Checksum = append([]byte(nil), testPkg.Checksum...)
	tampered.Checksum[0] ^= 0xff

	repo := Repository{URI: fmt.Sprintf("%s/%s", testAlpineRepos, testArch)}
	repoWithIndex := repo.WithIndex(&APKIndex{Packages: []*Package{&tampered}})
	pkg := NewRepositoryPackage(&tampered, repoWithIndex)
	ctx := context.Background()

	tmpDir := t.TempDir()
	httpClient := &http.Client{Transport: &testLocalTransport{root: testPrimaryPkgDir, basenameOnly: true}}
	a := newDefaultPackageGetter(httpClient, &cache{
		dir:     tmpDir,
		offline: false,
		shared:  NewCache(false),
	}, auth.DefaultAuthenticators)

	_, err := a.GetPackage(ctx, pkg)
	require.Error(t, err, "expected checksum mismatch to be detected")
	require.Contains(t, err.Error(), "control hash mismatch")
}

// TestCachedPackage_TamperedControl confirms that a cache entry whose
// on-disk control file no longer matches its content-addressable filename
// is rejected rather than served. This protects against cache corruption
// or tampering after an entry was originally written.
func TestCachedPackage_TamperedControl(t *testing.T) {
	repo := Repository{URI: fmt.Sprintf("%s/%s", testAlpineRepos, testArch)}
	repoWithIndex := repo.WithIndex(&APKIndex{Packages: []*Package{&testPkg}})
	pkg := NewRepositoryPackage(&testPkg, repoWithIndex)
	ctx := context.Background()

	tmpDir := t.TempDir()
	httpClient := &http.Client{Transport: &testLocalTransport{root: testPrimaryPkgDir, basenameOnly: true}}
	a := newDefaultPackageGetter(httpClient, &cache{
		dir:     tmpDir,
		offline: false,
		shared:  NewCache(false),
	}, auth.DefaultAuthenticators)

	// Populate the cache.
	exp, err := a.GetPackage(ctx, pkg)
	require.NoError(t, err, "populating cache")
	ctlPath := exp.ControlFile
	require.FileExists(t, ctlPath)

	cacheDir := filepath.Dir(ctlPath)

	// Tamper with the cached control file. Overwrite with different bytes
	// so its SHA-1 no longer matches the content-addressable filename.
	require.NoError(t, os.WriteFile(ctlPath, []byte("tampered"), 0o644))

	_, err = a.cachedPackage(ctx, pkg, cacheDir)
	require.Error(t, err, "expected tampered cache entry to be rejected")
	require.Contains(t, err.Error(), "control hash mismatch")
}

// attackerTar builds a structurally valid tar carrying one attacker-chosen
// file. It is deliberately well-formed: a tar full of garbage is rejected by
// tar parsing rather than by any integrity check, which makes a crude tamper
// test look like a non-finding.
func attackerTar(t *testing.T) []byte {
	t.Helper()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	body := []byte("#!/bin/sh\n# attacker payload\n")
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name:     "bin/pwned",
		Typeflag: tar.TypeReg,
		Mode:     0o755,
		Size:     int64(len(body)),
		Format:   tar.FormatPAX,
	}))
	_, err := tw.Write(body)
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	return buf.Bytes()
}

// gzipped returns b as a single gzip member.
func gzipped(t *testing.T, b []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err := zw.Write(b)
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

// fsNames returns every entry name in the indexed tar, sorted.
//
// Deliberately not fs.WalkDir: tarfs indexes each entry under path.Dir of its
// header name, which files a top-level "etc/" under "etc" rather than under
// ".", so a walk from the root yields only "." itself. A comparison built on
// that would pass no matter what the archive held.
func fsNames(t *testing.T, fsys *tarfs.FS) []string {
	t.Helper()

	entries := fsys.Entries()
	require.NotEmpty(t, entries, "indexed tar has no entries")
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		// Header.Name, not Name(): Entry implements fs.DirEntry, whose Name()
		// method returns only the base name.
		names = append(names, e.Header.Name)
	}
	sort.Strings(names)
	return names
}

func sha256File(t *testing.T, path string) []byte {
	t.Helper()

	b, err := os.ReadFile(path)
	require.NoError(t, err)
	sum := sha256.Sum256(b)
	return sum[:]
}

// TestCachedPackage_TamperedData is the data-section analogue of
// TestCachedPackage_TamperedControl. The control section is verified against
// the Q1 checksum carried in the signed index, which is what makes the
// datahash in .PKGINFO trustworthy; the data section must in turn be chained
// back to that datahash or an attacker who can write to the cache can swap in
// arbitrary package contents while PackageHash still reports the legitimate
// digest.
//
// Two properties are easy to get wrong here and each has its own case below:
//
//   - The file actually served is <datahash>.dat.tar, not <datahash>.dat.tar.gz;
//     PackageData() prefers the uncompressed file and only falls back to
//     decompressing the .gz when it is absent. Verifying only the .gz leaves the
//     primary vector open.
//   - datahash covers the *compressed* stream, so the uncompressed tar has no
//     authenticated digest of its own anywhere in the apk format. It can only be
//     trusted as a derivative of the verified .gz.
func TestCachedPackage_TamperedData(t *testing.T) {
	repo := Repository{URI: fmt.Sprintf("%s/%s", testAlpineRepos, testArch)}
	repoWithIndex := repo.WithIndex(&APKIndex{Packages: []*Package{&testPkg}})
	pkg := NewRepositoryPackage(&testPkg, repoWithIndex)
	ctx := context.Background()

	// cached describes a freshly populated cache entry for testPkg.
	type cached struct {
		dir     string      // the package's cache directory
		datGz   string      // <datahash>.dat.tar.gz
		datTar  string      // <datahash>.dat.tar
		tarSum  []byte      // sha256 of the legitimate uncompressed tar
		tarInfo os.FileInfo // Lstat of datTar as cachePackage left it
		names   []string    // every entry in the legitimate package
	}

	setup := func(t *testing.T) (*defaultPackageGetter, cached) {
		t.Helper()

		// cachedPackage is reached only on a disk-cache hit, so the in-memory
		// singleflight cache must not answer for us.
		globalApkCache.Forget(pkg.URL())
		t.Cleanup(func() { globalApkCache.Forget(pkg.URL()) })

		tmpDir := t.TempDir()
		httpClient := &http.Client{Transport: &testLocalTransport{root: testPrimaryPkgDir, basenameOnly: true}}
		a := newDefaultPackageGetter(httpClient, &cache{
			dir:     tmpDir,
			offline: false,
			shared:  NewCache(false),
		}, auth.DefaultAuthenticators)

		exp, err := a.GetPackage(ctx, pkg)
		require.NoError(t, err, "populating cache")

		tarInfo, err := os.Lstat(exp.TarFile)
		require.NoError(t, err)

		return a, cached{
			dir:     filepath.Dir(exp.ControlFile),
			datGz:   exp.PackageFile,
			datTar:  exp.TarFile,
			tarSum:  sha256File(t, exp.TarFile),
			tarInfo: tarInfo,
			names:   fsNames(t, exp.TarFS),
		}
	}

	for _, tc := range []struct {
		name string
		// tamper mutates the populated cache entry.
		tamper func(t *testing.T, c cached)
		// wantErr, when non-empty, is a substring of the expected rejection.
		wantErr string
		// verify runs on the accepted result when wantErr is empty.
		verify func(t *testing.T, c cached, exp *expandapk.APKExpanded)
	}{
		{
			name: "untampered cache entry is served without rewriting the cache",
			verify: func(t *testing.T, c cached, exp *expandapk.APKExpanded) {
				require.Equal(t, c.names, fsNames(t, exp.TarFS), "served contents differ from the cached package")

				// A verified hit must not rewrite the uncompressed tar: doing so
				// would orphan the file cachePackage advertised and double the
				// cache's on-disk footprint.
				after, err := os.Lstat(c.datTar)
				require.NoError(t, err)
				require.True(t, os.SameFile(c.tarInfo, after),
					"verified cache hit replaced %s (was mode %v, now mode %v)", c.datTar, c.tarInfo.Mode(), after.Mode())
				require.Equal(t, c.tarSum, sha256File(t, c.datTar))
			},
		},
		{
			// Was the primary vector, when the cached uncompressed tar was what
			// got served. It is no longer read at all, so this is now a test that
			// its contents cannot matter.
			name: "attacker tar swapped into .dat.tar is not served",
			tamper: func(t *testing.T, c cached) {
				require.NoError(t, os.WriteFile(c.datTar, attackerTar(t), 0o644))
			},
			verify: func(t *testing.T, c cached, exp *expandapk.APKExpanded) {
				_, err := fs.ReadFile(exp.TarFS, "bin/pwned")
				require.Error(t, err, "attacker payload was readable through the returned TarFS")
				require.Equal(t, c.names, fsNames(t, exp.TarFS))
			},
		},
		{
			// Same swap, but reached through a symlink rather than by
			// overwriting in place.
			name: "attacker tar reached via a .dat.tar symlink is not served",
			tamper: func(t *testing.T, c cached) {
				elsewhere := filepath.Join(t.TempDir(), "planted.tar")
				require.NoError(t, os.WriteFile(elsewhere, attackerTar(t), 0o644))
				require.NoError(t, os.Remove(c.datTar))
				require.NoError(t, os.Symlink(elsewhere, c.datTar))
			},
			verify: func(t *testing.T, c cached, exp *expandapk.APKExpanded) {
				_, err := fs.ReadFile(exp.TarFS, "bin/pwned")
				require.Error(t, err, "attacker payload was readable through the returned TarFS")
				require.Equal(t, c.names, fsNames(t, exp.TarFS))
			},
		},
		{
			name: "attacker tar.gz swapped into .dat.tar.gz is rejected",
			tamper: func(t *testing.T, c cached) {
				require.NoError(t, os.WriteFile(c.datGz, gzipped(t, attackerTar(t)), 0o644))
			},
			wantErr: "data hash mismatch",
		},
		{
			// The uncompressed file is not consulted either way, so removing it
			// changes nothing: the .gz is still what is measured and inflated.
			name: "attacker tar.gz swapped in with .dat.tar removed is rejected",
			tamper: func(t *testing.T, c cached) {
				require.NoError(t, os.Remove(c.datTar))
				require.NoError(t, os.WriteFile(c.datGz, gzipped(t, attackerTar(t)), 0o644))
			},
			wantErr: "data hash mismatch",
		},
		{
			// Corruption short of tampering is caught by the same digest check,
			// and caught before any of it is decompressed.
			name: "truncated .dat.tar.gz is rejected",
			tamper: func(t *testing.T, c cached) {
				b, err := os.ReadFile(c.datGz)
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(c.datGz, b[:len(b)/2], 0o644))
			},
			wantErr: "data hash mismatch",
		},
		{
			name: "non-gzip .dat.tar.gz is rejected",
			tamper: func(t *testing.T, c cached) {
				require.NoError(t, os.WriteFile(c.datGz, []byte("not a gzip stream"), 0o644))
			},
			wantErr: "data hash mismatch",
		},
		{
			name: "missing .dat.tar.gz is rejected even when .dat.tar is present",
			tamper: func(t *testing.T, c cached) {
				require.NoError(t, os.Remove(c.datGz))
			},
			// Not the path: it is interpolated into nearly every error this code
			// emits, so matching on it would accept an unrelated failure.
			wantErr: "no such file or directory",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, c := setup(t)
			if tc.tamper != nil {
				tc.tamper(t, c)
			}

			exp, err := a.cachedPackage(ctx, pkg, c.dir)

			if tc.wantErr != "" {
				require.Error(t, err, "expected the tampered cache entry to be rejected, got %+v", exp)
				require.Contains(t, err.Error(), tc.wantErr, "wrong rejection reason")
				return
			}
			require.NoError(t, err, "legitimate cache entry was rejected")
			require.Equal(t, testPkg.Checksum, exp.ControlHash)
			// A served entry must also be reusable from the in-memory cache.
			// IsValid deliberately skips the handle-name check for a private
			// copy -- it is unlinked, so there is no name to stat -- which makes
			// this a check that the skip is reached rather than that the name
			// resolves.
			require.True(t, exp.IsValid(), "served entry does not survive IsValid")
			tc.verify(t, c, exp)
		})
	}
}

// TestGetPackage_PoisonedCacheIsRepaired covers the whole GetPackage path, not
// just cachedPackage's rejection.
//
// Rejecting a poisoned entry only turns into a cache miss, and the refetch that
// follows has to install its verified download over the poison. If it defers to
// what is already there -- which is what AdvertiseCachedFile does, since it
// assumes an existing entry was put there by a cooperating process -- then the
// planted files survive their own rejection and get served anyway, and the
// rejection recurs on every call because nothing ever replaces them. Verifying
// the read side alone does not close the hole.
func TestGetPackage_PoisonedCacheIsRepaired(t *testing.T) {
	repo := Repository{URI: fmt.Sprintf("%s/%s", testAlpineRepos, testArch)}
	repoWithIndex := repo.WithIndex(&APKIndex{Packages: []*Package{&testPkg}})
	pkg := NewRepositoryPackage(&testPkg, repoWithIndex)
	ctx := context.Background()

	globalApkCache.Forget(pkg.URL())
	t.Cleanup(func() { globalApkCache.Forget(pkg.URL()) })

	tmpDir := t.TempDir()
	httpClient := &http.Client{Transport: &testLocalTransport{root: testPrimaryPkgDir, basenameOnly: true}}
	a := newDefaultPackageGetter(httpClient, &cache{
		dir:     tmpDir,
		offline: false,
		shared:  NewCache(false),
	}, auth.DefaultAuthenticators)

	exp, err := a.GetPackage(ctx, pkg)
	require.NoError(t, err, "populating cache")
	datGz, datTar := exp.PackageFile, exp.TarFile
	cacheDir := filepath.Dir(exp.ControlFile)
	wantNames := fsNames(t, exp.TarFS)
	wantTarSum := sha256File(t, datTar)
	wantGzSum := sha256File(t, datGz)

	// Poison both halves of the data section. Replacing only the uncompressed
	// tar is inert, since nothing reads it; poisoning the .gz is what fails the
	// digest, forces the refetch, and so exercises the install-over-poison path.
	evil := attackerTar(t)
	require.NoError(t, os.Remove(datGz))
	require.NoError(t, os.WriteFile(datGz, gzipped(t, evil), 0o644))
	require.NoError(t, os.Remove(datTar))
	require.NoError(t, os.WriteFile(datTar, evil, 0o644))

	globalApkCache.Forget(pkg.URL())
	_, err = a.cachedPackage(ctx, pkg, cacheDir)
	require.Error(t, err, "poisoned entry should be rejected on the read path")
	require.Contains(t, err.Error(), "data hash mismatch")

	globalApkCache.Forget(pkg.URL())
	got, err := a.GetPackage(ctx, pkg)
	require.NoError(t, err, "refetch after rejection should succeed")

	_, err = fs.ReadFile(got.TarFS, "bin/pwned")
	require.Error(t, err, "attacker payload was served after the repair refetch")
	require.Equal(t, wantNames, fsNames(t, got.TarFS))

	// The repair has to land on disk, or every later call rejects and refetches
	// again -- a warm cache turned into an unbounded download loop, and a hard
	// failure when offline.
	require.Equal(t, wantTarSum, sha256File(t, datTar), "poisoned .dat.tar survived the repair")
	// Compared against the known-good digest, not against the raw attacker tar:
	// this file was poisoned with the *gzipped* form, so comparing it to the
	// uncompressed bytes could never fail and would assert nothing.
	require.Equal(t, wantGzSum, sha256File(t, datGz), "poisoned .dat.tar.gz survived the repair")

	globalApkCache.Forget(pkg.URL())
	_, err = a.cachedPackage(ctx, pkg, cacheDir)
	require.NoError(t, err, "cache still rejects after a repair refetch")
}

// TestCachedPackageSurvivesInPlaceRewrite is the regression test for the way
// the first attempt at this fix was bypassed.
//
// Verifying a file and then reading it again later is not a verification: it is
// two reads of a mutable object. An attacker who overwrites the cache entry in
// place -- same inode, same length, no rename and no unlink -- leaves every
// identity check intact while changing every byte that gets served. IsValid
// compares device and inode, so it does not notice either, which made the
// poison stick for the rest of the process via the in-memory cache.
//
// Nothing here should be reachable now, because what is served is inflated into
// an unlinked copy that has no name for an attacker to write to.
func TestCachedPackageSurvivesInPlaceRewrite(t *testing.T) {
	ctx := context.Background()
	repo := Repository{URI: fmt.Sprintf("%s/%s", testAlpineRepos, testArch)}
	repoWithIndex := repo.WithIndex(&APKIndex{Packages: []*Package{&testPkg}})
	pkg := NewRepositoryPackage(&testPkg, repoWithIndex)

	globalApkCache.Forget(pkg.URL())
	t.Cleanup(func() { globalApkCache.Forget(pkg.URL()) })

	httpClient := &http.Client{Transport: &testLocalTransport{root: testPrimaryPkgDir, basenameOnly: true}}
	a := newDefaultPackageGetter(httpClient, &cache{
		dir:     t.TempDir(),
		offline: false,
		shared:  NewCache(false),
	}, auth.DefaultAuthenticators)

	exp, err := a.GetPackage(ctx, pkg)
	require.NoError(t, err, "populating cache")

	// Assert on file *contents*, not on the entry list: tarfs builds its index
	// eagerly and keeps it in memory, so names survive a poisoning that changes
	// every byte served. Content is read lazily through the descriptor, which is
	// exactly what the attack targets.
	victim := firstRegularFile(t, exp.TarFS)
	want, err := fs.ReadFile(exp.TarFS, victim)
	require.NoError(t, err)
	require.NotEmpty(t, want, "need a non-empty file to detect a rewrite")

	// Overwrite in place, without changing any file's identity or length.
	for _, path := range []string{exp.TarFile, exp.PackageFile} {
		info, err := os.Stat(path)
		require.NoError(t, err)
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		require.NoError(t, err, "opening %s for the in-place rewrite", path)
		_, err = f.WriteAt(bytes.Repeat([]byte("P"), int(info.Size())), 0)
		require.NoError(t, err)
		require.NoError(t, f.Close())
	}

	// The descriptor already in hand must be unaffected.
	got, err := fs.ReadFile(exp.TarFS, victim)
	require.NoError(t, err, "reading %s after the in-place rewrite", victim)
	require.Equal(t, want, got,
		"an in-place rewrite of the cache changed what the verified descriptor serves for %s", victim)

	// And the in-memory cache must not launder the poison into later calls.
	// IsValid cannot detect an in-place rewrite, so this only holds because the
	// bytes it is holding never came from a file the attacker can reach.
	again, err := a.GetPackage(ctx, pkg)
	require.NoError(t, err)
	got, err = fs.ReadFile(again.TarFS, victim)
	require.NoError(t, err)
	require.Equal(t, want, got, "a later GetPackage served content from the rewritten cache entry")
}

// firstRegularFile returns the name of a non-empty regular file in fsys, for
// tests that need something whose contents can be compared.
func firstRegularFile(t *testing.T, fsys *tarfs.FS) string {
	t.Helper()

	// Decided by what actually reads back, rather than by inspecting modes: the
	// only property this needs is "has content we can compare".
	for _, name := range fsNames(t, fsys) {
		if b, err := fs.ReadFile(fsys, name); err == nil && len(b) > 0 {
			return name
		}
	}
	t.Fatal("no readable non-empty file in the test package")
	return ""
}

// TestInstallDoesNotReadTheCachedTar covers the install half of the fix.
// Verification happens when the cache is read, but installation happens later,
// so anything installPackage reopens by path is a fresh, unverified read of a
// directory we do not trust. It must install from the descriptor that was
// verified, which is a private copy nothing else can reach.
//
// Concretely this pins expandedContents.PackageData, the PackageDataStreamer
// the non-WriteHeaderer branch resolves. That accessor delegated to
// expandapk.APKExpanded.PackageData when PackageContents was introduced, which
// re-admitted the cache entry by name; this is the case that catches it.
func TestInstallDoesNotReadTheCachedTar(t *testing.T) {
	ctx := context.Background()
	repo := Repository{URI: fmt.Sprintf("%s/%s", testAlpineRepos, testArch)}
	repoWithIndex := repo.WithIndex(&APKIndex{Packages: []*Package{&testPkg}})
	pkg := NewRepositoryPackage(&testPkg, repoWithIndex)

	apk, src, err := testGetTestAPK()
	require.NoError(t, err)
	// The branch under test is the one taken when the target fs is not a
	// WriteHeaderer; assert that, or this silently measures the lazy branch.
	_, isWH := apk.fs.(WriteHeaderer)
	require.False(t, isWH, "test fs implements WriteHeaderer; this would exercise the lazy install branch instead")

	globalApkCache.Forget(pkg.URL())
	t.Cleanup(func() { globalApkCache.Forget(pkg.URL()) })

	httpClient := &http.Client{Transport: &testLocalTransport{root: testPrimaryPkgDir, basenameOnly: true}}
	a := newDefaultPackageGetter(httpClient, &cache{
		dir:     t.TempDir(),
		offline: false,
		shared:  NewCache(false),
	}, auth.DefaultAuthenticators)

	exp, err := a.GetPackage(ctx, pkg)
	require.NoError(t, err, "populating cache")

	// The attacker wins the window between verification and installation.
	require.NoError(t, os.Remove(exp.TarFile))
	require.NoError(t, os.WriteFile(exp.TarFile, attackerTar(t), 0o644))

	installed, err := apk.installPackage(ctx, &testPkg, ExpandedContents(exp), nil)
	require.NoError(t, err, "installing a verified package")

	names := make([]string, 0, len(installed))
	for _, h := range installed {
		names = append(names, h.Name)
	}
	require.NotContains(t, names, "bin/pwned",
		"installPackage read the cached tar by path instead of the verified descriptor")
	require.Greater(t, len(names), 1, "expected the real package contents, got %v", names)

	_, err = src.Stat("bin/pwned")
	require.Error(t, err, "attacker payload landed in the target filesystem")
}

// TestCachedPackageHonoursDataSizeLimit proves a configured decompression limit
// actually reaches the cache-read path, which builds its APKExpanded by hand and
// so does not pick limits up from ExpandApkWithOptions.
func TestCachedPackageHonoursDataSizeLimit(t *testing.T) {
	ctx := context.Background()
	repo := Repository{URI: fmt.Sprintf("%s/%s", testAlpineRepos, testArch)}
	repoWithIndex := repo.WithIndex(&APKIndex{Packages: []*Package{&testPkg}})
	pkg := NewRepositoryPackage(&testPkg, repoWithIndex)

	globalApkCache.Forget(pkg.URL())
	t.Cleanup(func() { globalApkCache.Forget(pkg.URL()) })

	httpClient := &http.Client{Transport: &testLocalTransport{root: testPrimaryPkgDir, basenameOnly: true}}
	shared := &cache{dir: t.TempDir(), offline: false, shared: NewCache(false)}
	warm := newDefaultPackageGetter(httpClient, shared, auth.DefaultAuthenticators)
	exp, err := warm.GetPackage(ctx, pkg)
	require.NoError(t, err, "populating cache")
	cacheDir := filepath.Dir(exp.ControlFile)
	tarInfo, err := os.Stat(exp.TarFile)
	require.NoError(t, err)

	for _, tc := range []struct {
		name    string
		opts    []packageGetterOption
		wantErr string
	}{
		{name: "no configured limit serves the entry"},
		{name: "unlimited serves the entry", opts: []packageGetterOption{withAPKDataMaxSize(-1)}},
		{
			name: "a limit above the data section serves the entry",
			opts: []packageGetterOption{withAPKDataMaxSize(tarInfo.Size() + 1)},
		},
		{
			// Below the compressed section, so openRegular's gate rejects it
			// before anything is hashed or inflated.
			name:    "a limit below the compressed section is caught before hashing",
			opts:    []packageGetterOption{withAPKDataMaxSize(1024)},
			wantErr: "byte limit",
		},
		{
			// Above the compressed section but below what it inflates to, so the
			// limit is enforced during decompression instead.
			name:    "a limit below the decompressed section is caught during inflation",
			opts:    []packageGetterOption{withAPKDataMaxSize(16384)},
			wantErr: "size limit exceeded",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			globalApkCache.Forget(pkg.URL())
			a := newDefaultPackageGetter(httpClient, shared, auth.DefaultAuthenticators, tc.opts...)

			got, err := a.cachedPackage(ctx, pkg, cacheDir)
			if tc.wantErr == "" {
				require.NoError(t, err, "want the cached entry served with opts %v", tc.opts)
				require.NotNil(t, got)
				return
			}
			require.Error(t, err, "want the configured limit to reject the cached entry")
			require.Contains(t, err.Error(), tc.wantErr, "wrong rejection reason")
		})
	}
}

// BenchmarkCachedPackage measures a warm disk-cache hit. cachedPackage has to
// decompress the data section to prove the tar it serves derives from the
// datahash-verified stream, so this is the hot path that integrity check taxes.
func BenchmarkCachedPackage(b *testing.B) {
	repo := Repository{URI: fmt.Sprintf("%s/%s", testAlpineRepos, testArch)}
	repoWithIndex := repo.WithIndex(&APKIndex{Packages: []*Package{&testPkg}})
	pkg := NewRepositoryPackage(&testPkg, repoWithIndex)
	ctx := context.Background()

	globalApkCache.Forget(pkg.URL())
	b.Cleanup(func() { globalApkCache.Forget(pkg.URL()) })

	httpClient := &http.Client{Transport: &testLocalTransport{root: testPrimaryPkgDir, basenameOnly: true}}
	a := newDefaultPackageGetter(httpClient, &cache{
		dir:     b.TempDir(),
		offline: false,
		shared:  NewCache(false),
	}, auth.DefaultAuthenticators)

	exp, err := a.GetPackage(ctx, pkg)
	require.NoError(b, err, "populating cache")
	b.Cleanup(func() { _ = exp.TarFS.Close() })
	cacheDir := filepath.Dir(exp.ControlFile)

	// Per op: the control section is read twice (hashed, then parsed), the
	// compressed section twice (hashed, then inflated), and the uncompressed tar
	// is written once into the private copy then read back once to index it.
	// Reporting only the tar size would credit the run with throughput over a
	// stream it never processes, and would flatter any change that drops a pass.
	tarInfo, err := os.Stat(exp.TarFile)
	require.NoError(b, err)
	gzInfo, err := os.Stat(exp.PackageFile)
	require.NoError(b, err)
	ctlInfo, err := os.Stat(exp.ControlFile)
	require.NoError(b, err)
	b.SetBytes(2*ctlInfo.Size() + 2*gzInfo.Size() + 2*tarInfo.Size())

	b.ResetTimer()
	for b.Loop() {
		got, err := a.cachedPackage(ctx, pkg, cacheDir)
		if err != nil {
			b.Fatal(err)
		}
		// Without this the verified handle from each iteration accumulates and
		// the benchmark eventually dies on EMFILE instead of measuring anything.
		if err := got.TarFS.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

// TestGetPackage_HashVerification confirms that GetPackage checks both the
// control hash and the data hash and that each failure path returns a
// distinguishable error. A synthetic APK is used so the test is fully
// self-contained and will regress if either check is removed.
func TestGetPackage_HashVerification(t *testing.T) {
	ctx := context.Background()
	getter := newDefaultPackageGetter(http.DefaultClient, nil, auth.DefaultAuthenticators)

	entries := []testDirEntry{
		{path: "usr/", dir: true, perms: 0o755},
		{path: "usr/bin/hello", perms: 0o755, content: []byte("hello")},
	}

	t.Run("success", func(t *testing.T) {
		ip := fakePackage(t, &Package{Name: "testpkg", Version: "1.0.0-r0"}, entries, "")
		exp, err := getter.GetPackage(ctx, ip)
		require.NoError(t, err)
		require.NotNil(t, exp)
		_ = exp.Close()
	})

	t.Run("control hash mismatch", func(t *testing.T) {
		ip := fakePackage(t, &Package{Name: "testpkg", Version: "1.0.0-r0"}, entries, "")
		ip.checksum = "Q1" + base64.StdEncoding.EncodeToString(make([]byte, 20)) // all-zero SHA-1
		_, err := getter.GetPackage(ctx, ip)
		require.Error(t, err)
		require.Contains(t, err.Error(), "control hash mismatch")
	})

	t.Run("data hash mismatch", func(t *testing.T) {
		wrongHash := fmt.Sprintf("%x", make([]byte, 32)) // 32 zero bytes, hex-encoded
		ip := fakePackage(t, &Package{Name: "testpkg", Version: "1.0.0-r0"}, entries, wrongHash)
		_, err := getter.GetPackage(ctx, ip)
		require.Error(t, err)
		require.Contains(t, err.Error(), "data hash mismatch")
	})
}

func TestIsRetryableError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"context canceled", context.Canceled, false},
		{"context deadline", context.DeadlineExceeded, false},
		{"unexpected EOF", io.ErrUnexpectedEOF, true},
		{"wrapped unexpected EOF", fmt.Errorf("expanding foo: %w", io.ErrUnexpectedEOF), true},
		{"connection reset", syscall.ECONNRESET, true},
		{"connection aborted", syscall.ECONNABORTED, true},
		{"net.OpError", &net.OpError{Op: "read", Err: errors.New("reset")}, true},
		{"string unexpected EOF", errors.New("something unexpected EOF happened"), true},
		{"string connection reset", errors.New("connection reset by peer"), true},
		{"string broken pipe", errors.New("write: broken pipe"), true},
		{"http 500", &httpStatusError{statusCode: 500, status: "500 Internal Server Error", url: "https://example.com/pkg.apk"}, true},
		{"http 502", &httpStatusError{statusCode: 502, status: "502 Bad Gateway", url: "https://example.com/pkg.apk"}, true},
		{"http 429", &httpStatusError{statusCode: 429, status: "429 Too Many Requests", url: "https://example.com/pkg.apk"}, true},
		{"http 404", &httpStatusError{statusCode: 404, status: "404 Not Found", url: "https://example.com/pkg.apk"}, false},
		{"wrapped http 503", fmt.Errorf("fetching package: %w", &httpStatusError{statusCode: 503, status: "503 Service Unavailable", url: "https://example.com/pkg.apk"}), true},
		{"checksum mismatch", errors.New("control hash mismatch: expected abc, got def"), false},
		{"generic error", errors.New("some other error"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isRetryableError(tt.err)
			require.Equal(t, tt.want, got)
		})
	}
}

// truncatingTransport serves a valid APK file but truncates the response on the first N requests.
type truncatingTransport struct {
	root      string
	failCount int32 // number of remaining requests to truncate
	attempts  atomic.Int32
}

func (t *truncatingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	attempt := t.attempts.Add(1)

	filename := filepath.Base(req.URL.Path)
	data, err := os.ReadFile(filepath.Join(t.root, filename))
	if err != nil {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(strings.NewReader("not found")),
		}, nil
	}

	if attempt <= atomic.LoadInt32(&t.failCount) {
		// Return a truncated response to simulate unexpected EOF during decompression.
		truncated := data[:len(data)/2]
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(string(truncated))),
		}, nil
	}

	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(string(data))),
	}, nil
}

func TestGetPackage_RetryOnTransientError(t *testing.T) {
	repo := Repository{URI: fmt.Sprintf("%s/%s", testAlpineRepos, testArch)}
	repoWithIndex := repo.WithIndex(&APKIndex{Packages: []*Package{&testPkg}})
	pkg := NewRepositoryPackage(&testPkg, repoWithIndex)
	ctx := context.Background()

	tr := &truncatingTransport{
		root:      testPrimaryPkgDir,
		failCount: 1, // fail once, then succeed
	}

	getter := newDefaultPackageGetter(
		&http.Client{Transport: tr},
		nil,
		auth.DefaultAuthenticators,
	)

	exp, err := getter.GetPackage(ctx, pkg)
	require.NoError(t, err, "expected retry to succeed")
	require.NotNil(t, exp)
	_ = exp.Close()

	// Should have taken 2 attempts (1 failure + 1 success).
	require.Equal(t, int32(2), tr.attempts.Load(), "expected exactly 2 fetch attempts")
}

func TestGetPackage_NoRetryOnPermanentError(t *testing.T) {
	tampered := testPkg
	tampered.Checksum = make([]byte, len(testPkg.Checksum)) // wrong checksum
	ctx := context.Background()

	repo := Repository{URI: fmt.Sprintf("%s/%s", testAlpineRepos, testArch)}
	repoWithIndex := repo.WithIndex(&APKIndex{Packages: []*Package{&tampered}})
	pkg := NewRepositoryPackage(&tampered, repoWithIndex)

	// Use a transport that always serves the real APK data so we can count attempts.
	tr := &truncatingTransport{
		root:      testPrimaryPkgDir,
		failCount: 0, // never truncate — always serve valid data
	}

	getter := newDefaultPackageGetter(
		&http.Client{Transport: tr},
		nil,
		auth.DefaultAuthenticators,
	)

	_, err := getter.GetPackage(ctx, pkg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "control hash mismatch")

	// Should have attempted exactly once — permanent errors must not be retried.
	require.Equal(t, int32(1), tr.attempts.Load(), "expected exactly 1 fetch attempt for permanent error")
}
