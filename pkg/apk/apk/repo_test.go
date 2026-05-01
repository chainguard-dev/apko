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

package apk

import (
	"context"
	"encoding/base32"
	"fmt"
	"io/fs"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"chainguard.dev/apko/pkg/apk/auth"
	apkfs "chainguard.dev/apko/pkg/apk/fs"
)

var (
	testAlpineRepos = "https://dl-cdn.alpinelinux.org/alpine/v3.16/main"
	testKeys        = map[string]string{
		"alpine-devel@lists.alpinelinux.org-616ae350.rsa.pub": `
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAyduVzi1mWm+lYo2Tqt/0
XkCIWrDNP1QBMVPrE0/ZlU2bCGSoo2Z9FHQKz/mTyMRlhNqTfhJ5qU3U9XlyGOPJ
piM+b91g26pnpXJ2Q2kOypSgOMOPA4cQ42PkHBEqhuzssfj9t7x47ppS94bboh46
xLSDRff/NAbtwTpvhStV3URYkxFG++cKGGa5MPXBrxIp+iZf9GnuxVdST5PGiVGP
ODL/b69sPJQNbJHVquqUTOh5Ry8uuD2WZuXfKf7/C0jC/ie9m2+0CttNu9tMciGM
EyKG1/Xhk5iIWO43m4SrrT2WkFlcZ1z2JSf9Pjm4C2+HovYpihwwdM/OdP8Xmsnr
DzVB4YvQiW+IHBjStHVuyiZWc+JsgEPJzisNY0Wyc/kNyNtqVKpX6dRhMLanLmy+
f53cCSI05KPQAcGj6tdL+D60uKDkt+FsDa0BTAobZ31OsFVid0vCXtsbplNhW1IF
HwsGXBTVcfXg44RLyL8Lk/2dQxDHNHzAUslJXzPxaHBLmt++2COa2EI1iWlvtznk
Ok9WP8SOAIj+xdqoiHcC4j72BOVVgiITIJNHrbppZCq6qPR+fgXmXa+sDcGh30m6
9Wpbr28kLMSHiENCWTdsFij+NQTd5S47H7XTROHnalYDuF1RpS+DpQidT5tUimaT
JZDr++FjKrnnijbyNF8b98UCAwEAAQ==
-----END PUBLIC KEY-----`,
		"alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub": `
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAutQkua2CAig4VFSJ7v54
ALyu/J1WB3oni7qwCZD3veURw7HxpNAj9hR+S5N/pNeZgubQvJWyaPuQDm7PTs1+
tFGiYNfAsiibX6Rv0wci3M+z2XEVAeR9Vzg6v4qoofDyoTbovn2LztaNEjTkB+oK
tlvpNhg1zhou0jDVYFniEXvzjckxswHVb8cT0OMTKHALyLPrPOJzVtM9C1ew2Nnc
3848xLiApMu3NBk0JqfcS3Bo5Y2b1FRVBvdt+2gFoKZix1MnZdAEZ8xQzL/a0YS5
Hd0wj5+EEKHfOd3A75uPa/WQmA+o0cBFfrzm69QDcSJSwGpzWrD1ScH3AK8nWvoj
v7e9gukK/9yl1b4fQQ00vttwJPSgm9EnfPHLAtgXkRloI27H6/PuLoNvSAMQwuCD
hQRlyGLPBETKkHeodfLoULjhDi1K2gKJTMhtbnUcAA7nEphkMhPWkBpgFdrH+5z4
Lxy+3ek0cqcI7K68EtrffU8jtUj9LFTUC8dERaIBs7NgQ/LfDbDfGh9g6qVj1hZl
k9aaIPTm/xsi8v3u+0qaq7KzIBc9s59JOoA8TlpOaYdVgSQhHHLBaahOuAigH+VI
isbC9vmqsThF2QdDtQt37keuqoda2E6sL7PUvIyVXDRfwX7uMDjlzTxHTymvq2Ck
htBqojBnThmjJQFgZXocHG8CAwEAAQ==
-----END PUBLIC KEY-----`,
		"test-rsa256.rsa.pub": `
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEArPL3OE2edJeOFFvd3iXS
n8+VP4LDydDaqIVJYsMZvbeASmxxgmo7PTCnr0N8hzDrUEn9D4Tb2vK6HGkMh89v
RkC8EXCKKltAAHOYG40yUDhnrkIzbnUl1Y27I69I9xIojFBXhB+nUckDCmqEhM7h
dGuCKZVr+ABXEgpPy4jua0OXXKmgGGFNnMGXg5BJ8xQS6NjAje1clpqgTcW4vMDi
VCfosZtPEL1uh7MqoKa1f63PuegQhlXI5q++LQL4O7aQKdZvk9RFV2PyIIgLE2Dr
WVLqCI2k2veoYJiz83oiixcxiHVqVqyrnLIFPT+F4dbH6lC4JhcIVK4Vvg+uY2/z
gp090qRbje3H/VV9SsKpwj7ZbzSz4H5zyafs0ONDVvTIzmz3M1vLS+Au8NqRkGNj
dxV4ZyYalq7BWrI51SKt1EyWQxWwTQcwIaaAMUIqOsc3I6qIvDRoNTY+ORTNwrud
+6Ve5h3bP9UyEHnSHQBHOEzQzlLDawCUo4RcyPsFfMqhCrCBM1IAKCFm4aeaIr7Q
0x+r1NFiZkOsW2JrbKFaA4swQdPGtirtxvcyq4HBP1XW1mlujKKFV64nByfMEaRs
UUcx14yovgv54uwNX4c8BRSYAuU/enW7jrdPKpLWOzKuKcRg8f+sIpblF2m5Fbqp
guyM+Ks3c29KlRf3iX35Gt0CAwEAAQ==
-----END PUBLIC KEY-----
`,
	}
	testArch = "aarch64"
)

func TestGetRepositoryIndexes(t *testing.T) {
	prepLayout := func(t *testing.T, tr http.RoundTripper, cache string, repos []string) *APK {
		src := apkfs.NewMemFS()
		err := src.MkdirAll("etc/apk", 0o755)
		require.NoError(t, err, "unable to mkdir /etc/apk")
		err = src.WriteFile(archFilePath, []byte(testArch+"\n"), 0o644)
		require.NoErrorf(t, err, "unable to write arch")
		err = src.MkdirAll(keysDirPath, 0o755)
		require.NoError(t, err, "unable to mkdir /etc/apk/keys")
		for k, v := range testKeys {
			err = src.WriteFile(filepath.Join("etc/apk/keys/", k), []byte(v), 0o644)
			require.NoError(t, err, "unable to write key %s", k)
		}

		if len(repos) > 0 {
			err = src.WriteFile(reposFilePath, []byte(strings.Join(repos, "\n")), 0o644)
			require.NoErrorf(t, err, "unable to write repositories")
		} else {
			err = src.WriteFile(reposFilePath, []byte(testAlpineRepos), 0o644)
			require.NoErrorf(t, err, "unable to write repositories")
		}

		opts := []Option{WithFS(src), WithIgnoreMknodErrors(ignoreMknodErrors), WithTransport(tr)}
		if cache != "" {
			opts = append(opts, WithCache(cache, false, NewCache(false)))
		}
		a, err := New(t.Context(), opts...)
		require.NoError(t, err, "unable to create APK")

		// set a client so we use local testdata instead of heading out to the Internet each time
		return a
	}
	t.Run("no cache", func(t *testing.T) {
		a := prepLayout(t, &testLocalTransport{root: testPrimaryPkgDir, basenameOnly: true}, "", nil)
		indexes, err := a.GetRepositoryIndexes(context.Background(), false)
		require.NoErrorf(t, err, "unable to get indexes")
		require.Greater(t, len(indexes), 0, "no indexes found")
	})
	t.Run("RSA256 signed", func(t *testing.T) {
		a := prepLayout(t, &testLocalTransport{root: testRSA256IndexPkgDir, basenameOnly: true}, "", nil)
		indexes, err := a.GetRepositoryIndexes(context.Background(), false)
		require.NoErrorf(t, err, "unable to get indexes")
		require.Greater(t, len(indexes), 0, "no indexes found")
	})
	t.Run("cache miss no network", func(t *testing.T) {
		// we use a transport that always returns a 404 so we know we're not hitting the network
		// it should fail for a cache hit
		tmpDir := t.TempDir()
		a := prepLayout(t, &testLocalTransport{fail: true}, tmpDir, nil)
		_, err := a.GetRepositoryIndexes(context.Background(), false)
		require.Error(t, err, "should fail when no cache and no network")
	})
	t.Run("we can fetch, but do not cache indices without etag", func(t *testing.T) {
		// we use a transport that can read from the network
		// it should fail for a cache hit
		tmpDir := t.TempDir()
		a := prepLayout(t, &testLocalTransport{root: testPrimaryPkgDir, basenameOnly: true}, tmpDir, nil)

		indexes, err := a.GetRepositoryIndexes(context.Background(), false)
		require.NoErrorf(t, err, "unable to get indexes")
		require.Greater(t, len(indexes), 0, "no indexes found")

		require.NoError(t, filepath.WalkDir(tmpDir, func(path string, _ fs.DirEntry, _ error) error {
			if filepath.Ext(path) == ".etag" {
				t.Errorf("found etag file %q, expected none.", path)
			}
			return nil
		}))
	})
	t.Run("cache miss network should fill cache", func(t *testing.T) {
		// we use a transport that can read from the network
		// it should fail for a cache hit
		tmpDir := t.TempDir()
		a := prepLayout(t, &testLocalTransport{
			root:         testPrimaryPkgDir,
			basenameOnly: true,
			headers: map[string][]string{
				http.CanonicalHeaderKey("etag"): {"an-etag"},
			},
		}, tmpDir, []string{testAlpineRepos})
		// fill the cache
		repoDir := filepath.Join(tmpDir, url.QueryEscape(testAlpineRepos), testArch)

		indexes, err := a.GetRepositoryIndexes(context.Background(), false)
		require.NoErrorf(t, err, "unable to get indexes")
		require.Greater(t, len(indexes), 0, "no indexes found")
		// check that the contents are the same
		index1, err := os.ReadFile(filepath.Join(repoDir, "APKINDEX", base32.StdEncoding.EncodeToString([]byte("an-etag"))+".tar.gz"))
		require.NoError(t, err, "unable to read cache index file")
		index2, err := os.ReadFile(filepath.Join(testPrimaryPkgDir, indexFilename))
		require.NoError(t, err, "unable to read previous index file")
		require.Equal(t, index1, index2, "index files do not match")
	})
	t.Run("repo url with http basic auth", func(t *testing.T) {
		tmpDir := t.TempDir()
		a := prepLayout(t, &testLocalTransport{
			root:             testPrimaryPkgDir,
			basenameOnly:     true,
			requireBasicAuth: true,
		}, tmpDir, []string{"https://user:pass@dl-cdn.alpinelinux.org/alpine/v3.16/main"})

		ctx := context.Background()
		indexes, err := a.GetRepositoryIndexes(ctx, false)
		require.NoErrorf(t, err, "unable to get indexes")
		require.Greater(t, len(indexes), 0, "no indexes found")
	})
	t.Run("cache hit etag match", func(t *testing.T) {
		// it should succeed for a cache hit
		tmpDir := t.TempDir()
		testEtag := "test-etag"
		tr := &testLocalTransport{root: testPrimaryPkgDir, basenameOnly: true, headers: map[string][]string{http.CanonicalHeaderKey("etag"): {testEtag}}}

		// get our APK struct
		a := prepLayout(t, tr, tmpDir, nil)

		// Use the client to fill the cache.
		indexes, err := a.GetRepositoryIndexes(context.Background(), false)
		require.NoErrorf(t, err, "unable to get indexes")
		require.Greater(t, len(indexes), 0, "no indexes found")
		// Capture the initial index.
		index1 := indexes[0]

		// Update the transport to serve the same etag, but different content to
		// verify that we serve from the cache instead of the response.
		tr.root = testAlternatePkgDir

		indexes, err = a.GetRepositoryIndexes(context.Background(), false)
		require.NoErrorf(t, err, "unable to get indexes")
		require.Greater(t, len(indexes), 0, "no indexes found")
		// Capture the resulting index.
		index2 := indexes[0]

		// check that the contents are the same
		require.Equal(t, index1, index2, "index files do not match")
	})
	t.Run("cache hit etag miss", func(t *testing.T) {
		// it should succeed for a cache hit
		tmpDir := t.TempDir()
		testEtag := "test-etag"
		tr := &testLocalTransport{root: testPrimaryPkgDir, basenameOnly: true, headers: map[string][]string{http.CanonicalHeaderKey("etag"): {testEtag}}}

		// get our APK struct
		a := prepLayout(t, tr, tmpDir, nil)

		// Use the client to fill the cache.
		indexes, err := a.GetRepositoryIndexes(context.Background(), false)
		require.NoErrorf(t, err, "unable to get indexes")
		require.Greater(t, len(indexes), 0, "no indexes found")
		// Capture the initial index.
		index1 := indexes[0]

		// Update the transport to serve a different etag and different content,
		// to verify that when the etag changes we use the data from the
		// response.
		tr.root = testAlternatePkgDir
		tr.headers = map[string][]string{http.CanonicalHeaderKey("etag"): {testEtag + "change"}}

		indexes, err = a.GetRepositoryIndexes(context.Background(), false)
		require.NoErrorf(t, err, "unable to get indexes")
		require.Greater(t, len(indexes), 0, "no indexes found")
		// Capture the resulting index.
		index2 := indexes[0]

		// check that the contents are the same
		require.NotEqual(t, index1, index2, "index files do not match")
	})
	t.Run("test cache concurrency", func(t *testing.T) {
		// Use the same temp directory for the cache.
		tmpDir := t.TempDir()

		eg := errgroup.Group{}
		for i := range 100 {
			eg.Go(func() error {
				a := prepLayout(t, &testLocalTransport{
					root:         testPrimaryPkgDir,
					basenameOnly: true,
					headers:      map[string][]string{http.CanonicalHeaderKey("etag"): {fmt.Sprint(i)}},
				}, tmpDir, nil)
				indexes, err := a.GetRepositoryIndexes(context.Background(), false)
				require.NoErrorf(t, err, "unable to get indexes")
				require.Greater(t, len(indexes), 0, "no indexes found")
				return nil
			})
		}
		require.NoErrorf(t, eg.Wait(), "unable to get indexes")
	})
}

func TestIndexAuth_good(t *testing.T) {
	called := false
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if gotuser, gotpass, ok := r.BasicAuth(); !ok || gotuser != testUser || gotpass != testPass {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/x86_64")
		http.FileServer(http.Dir(testPrimaryPkgDir)).ServeHTTP(w, r)
	}))
	defer s.Close()
	host := strings.TrimPrefix(s.URL, "http://")

	ctx := context.Background()

	a, err := New(ctx, WithFS(apkfs.NewMemFS()),
		WithArch("x86_64"),
		WithAuthenticator(auth.StaticAuth(host, testUser, testPass)))
	require.NoErrorf(t, err, "unable to create APK")
	err = a.InitDB(ctx)
	require.NoError(t, err, "unable to init db")
	err = a.SetRepositories(ctx, []string{s.URL})
	require.NoError(t, err, "unable to set repositories")
	_, err = a.GetRepositoryIndexes(ctx, true)
	require.NoErrorf(t, err, "unable to get indexes")
	require.True(t, called, "did not make request")
}

func TestIndexAuth_bad(t *testing.T) {
	called := false
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if gotuser, gotpass, ok := r.BasicAuth(); !ok || gotuser != testUser || gotpass != testPass {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/x86_64")
		http.FileServer(http.Dir(testPrimaryPkgDir)).ServeHTTP(w, r)
	}))
	defer s.Close()
	host := strings.TrimPrefix(s.URL, "http://")

	ctx := context.Background()

	a, err := New(ctx, WithFS(apkfs.NewMemFS()),
		WithArch("x86_64"),
		WithAuthenticator(auth.StaticAuth(host, "baduser", "badpass")))
	require.NoErrorf(t, err, "unable to create APK")
	err = a.InitDB(ctx)
	require.NoError(t, err, "unable to init db")
	err = a.SetRepositories(ctx, []string{s.URL})
	require.NoError(t, err, "unable to set repositories")
	_, err = a.GetRepositoryIndexes(ctx, true)
	require.Error(t, err, "should fail with bad auth")
	require.True(t, called, "did not make request")
}

func testGetPackagesAndIndex() ([]*RepositoryPackage, []*RepositoryWithIndex) {
	// create a tree of packages, including some multiple that depend on the same one
	// but no circular dependencies; this is an acyclic graph
	// dependency chain:
	/*
			  dependency chain:
			  package1 -> dep1
		   	              -> dep4
		   	              -> dep5
			          -> dep2
			              -> dep3
			                  -> dep6
			                  -> cmd:/bin/foo (foo)
			                  -> so:libq.so (libq)
			              -> /bin/sh (busybox)
			          -> dep3
			            -> dep6
			            -> cmd:/bin/foo (foo)
			            -> so:libq.so (libq)
			  package2 -> dep2
			              -> dep3
			                  -> dep6
			                  -> cmd:/bin/foo (foo)
			                  -> so:libq.so (libq)
			              -> /bin/sh (busybox)
			          -> dep7
			  package3 -> dep8
			  package5 v1.0.0
			  package5 v1.5.0
			  package5 v1.5.1
			  package5 v2.0.0
	*/
	// a depth-first search gives the following for package1
	// dep5, dep4, dep1, libq, foo, dep6, dep3, busybox, dep2, libq, foo, dep6, dep3
	// when deduplicated by first-before-last (because we did depth-first),
	// we get
	// dep4, dep5, dep1, dep6, foo, libq, dep3, busybox, dep2
	var (
		packages = []*Package{
			{Name: "package1", Version: "1.0.0", Dependencies: []string{"dep1", "dep2", "dep3"}},
			{Name: "dep1", Version: "1.0.0", Dependencies: []string{"dep4", "dep5"}},
			{Name: "dep2", Version: "1.0.0", Dependencies: []string{"dep3", "/bin/sh"}},
			{Name: "dep3", Version: "1.0.0", Dependencies: []string{"dep6", "cmd:/bin/foo", "so:libq.so.1"}},
			{Name: "dep4", Version: "1.0.0", Dependencies: []string{}},
			{Name: "dep5", Version: "1.0.0", Dependencies: []string{}},
			{Name: "dep6", Version: "1.0.0", Dependencies: []string{}},
			{Name: "dep7", Version: "1.0.0", Dependencies: []string{}},
			{Name: "dep8", Version: "1.0.0", Dependencies: []string{"dep8"}},
			{Name: "libq", Version: "1.0.0", Dependencies: []string{}, Provides: []string{"so:libq.so.1"}},
			{Name: "foo", Version: "1.0.0", Dependencies: []string{}, Provides: []string{"cmd:/bin/foo"}},
			{Name: "busybox", Version: "1.0.0", Dependencies: []string{}, Provides: []string{"/bin/sh"}},
			{Name: "unused", Version: "1.0.0", Dependencies: []string{}},
			{Name: "package2", Version: "1.0.0", Dependencies: []string{"dep2", "dep7"}},
			{Name: "package3", Version: "1.0.0", Dependencies: []string{"dep8"}},
			{Name: "package5", Version: "1.0.0"},
			{Name: "package5", Version: "1.5.0"},
			{Name: "package5", Version: "1.5.1"},
			{Name: "package5", Version: "2.0.0"},
			{Name: "package5-special", Version: "1.2.0", Provides: []string{"package5"}},
			{Name: "package5-conflict", Version: "1.2.0", Provides: []string{"package5=1.2.0"}},
			{Name: "package5-noconflict", Version: "1.2.0", Provides: []string{"package5"}},
			{Name: "package6", Version: "1.5.1"},
			{Name: "package6", Version: "2.0.0", Dependencies: []string{"package6", "package5"}},
			{Name: "package7", Version: "1"},
			{Name: "package8", Version: "2", Provides: []string{"package7=0.9"}},
			{Name: "package9", Version: "2.0.0", Dependencies: []string{"package5"}},
			{Name: "abc9", Version: "2.0.0", Dependencies: []string{"package5"}},
			{Name: "locked-dep", Version: "2.0.0", Dependencies: []string{"package5=1.5.1"}},
		}
		repoPackages = make([]*RepositoryPackage, 0, len(packages))
	)

	for _, pkg := range packages {
		repoPackages = append(repoPackages, &RepositoryPackage{Package: pkg})
	}
	repo := Repository{}
	repoWithIndex := repo.WithIndex(&APKIndex{
		Packages: packages,
	})
	return repoPackages, []*RepositoryWithIndex{repoWithIndex}
}

func TestGetPackagesWithDependences(t *testing.T) {
	t.Run("names only", func(t *testing.T) {
		_, index := testGetPackagesAndIndex()

		names := []string{"package1", "package2"}
		expectedPackage1 := []string{"dep4", "dep5", "dep1", "busybox", "foo", "dep6", "libq", "dep3", "dep2", "package1"}
		expectedPackage2 := []string{"dep7", "package2"}
		expected := make([]string, 0, len(expectedPackage1)+len(expectedPackage2))
		expected = append(expected, expectedPackage1...)
		expected = append(expected, expectedPackage2...)
		// this should do a few things:
		// - find all of the dependencies of all of the packages
		// - eliminate duplicates
		// - reverse the order, so that it is in order of installation
		resolver := NewPkgResolver(context.Background(), testNamedRepositoryFromIndexes(index))
		pkgs, _, err := resolver.GetPackagesWithDependencies(context.Background(), names, nil)
		require.NoErrorf(t, err, "unable to get packages")
		actual := make([]string, 0, len(pkgs))
		for _, pkg := range pkgs {
			actual = append(actual, pkg.Name)
		}
		require.True(t, reflect.DeepEqual(expected, actual), "packages mismatch:\nactual %v\nexpect %v", actual, expected)
	})
	t.Run("dependency in world", func(t *testing.T) {
		// If a dependency is resolved by something in world, i.e. the explicit package list,
		// that should override anything that comes up in dependencies, even if a higher version.
		// This test checks that an override on something that provides package5, or even is package5,
		// even with a lower version, will take priority.
		// we use abc9 -> package5 rather than package9 -> package5, because world sorts alphabetically,
		// and we want to ensure that, even though abc9 is processed first, package5 override still works.
		_, index := testGetPackagesAndIndex()
		resolver := NewPkgResolver(context.Background(), testNamedRepositoryFromIndexes(index))
		t.Run("same name no lock", func(t *testing.T) {
			name, version := "package5", "2.0.0" //nolint:goconst // no, we do not want to make it a constant
			names := []string{name, "abc9"}
			sort.Strings(names)
			pkgs, _, err := resolver.GetPackagesWithDependencies(context.Background(), names, nil)
			require.NoErrorf(t, err, "unable to get packages")
			require.Len(t, pkgs, 2)
			for _, pkg := range pkgs {
				if pkg.Name != name {
					continue
				}
				require.Equal(t, version, pkg.Version)
			}
		})
		t.Run("same name locked", func(t *testing.T) {
			name, version := "package5", "1.5.1"
			names := []string{fmt.Sprintf("%s=%s", name, version), "abc9"}
			sort.Strings(names)
			pkgs, _, err := resolver.GetPackagesWithDependencies(context.Background(), names, nil)
			require.NoErrorf(t, err, "unable to get packages")
			require.Len(t, pkgs, 2)
			for _, pkg := range pkgs {
				if pkg.Name != name {
					continue
				}
				require.Equal(t, version, pkg.Version)
			}
		})
		t.Run("different name with provides", func(t *testing.T) {
			providesName, version := "package5-special", "1.2.0"
			names := []string{providesName, "abc9"}
			sort.Strings(names)
			pkgs, _, err := resolver.GetPackagesWithDependencies(context.Background(), names, nil)
			require.NoErrorf(t, err, "unable to get packages")
			require.Len(t, pkgs, 2)
			for _, pkg := range pkgs {
				if pkg.Name != providesName {
					continue
				}
				require.Equal(t, version, pkg.Version)
			}
		})
	})
	t.Run("conflicting same provides", func(t *testing.T) {
		// Test that we can't install both package5-special and package5-conflict
		// because they both provide package5.
		_, index := testGetPackagesAndIndex()
		resolver := NewPkgResolver(context.Background(), testNamedRepositoryFromIndexes(index))
		names := []string{"package5-special", "package5-noconflict", "abc9"}
		sort.Strings(names)
		_, _, err := resolver.GetPackagesWithDependencies(context.Background(), names, nil)
		require.NoError(t, err, "provided package should not conflict")
	})
	t.Run("conflicting provides", func(t *testing.T) {
		// Test that we can't install both package5-special and package5-conflict
		// because they both provide package5.
		_, index := testGetPackagesAndIndex()
		resolver := NewPkgResolver(context.Background(), testNamedRepositoryFromIndexes(index))
		names := []string{"package5-special", "package5-conflict", "abc9"}
		sort.Strings(names)
		_, _, err := resolver.GetPackagesWithDependencies(context.Background(), names, nil)
		require.Error(t, err, "provided package should conflict")
	})
	t.Run("locked versions", func(t *testing.T) {
		// Test that we can't install both package5-special and package5-conflict
		// because they both provide package5.
		_, index := testGetPackagesAndIndex()
		resolver := NewPkgResolver(context.Background(), testNamedRepositoryFromIndexes(index))
		names := []string{"package5", "locked-dep"}
		sort.Strings(names)
		install, _, err := resolver.GetPackagesWithDependencies(context.Background(), names, nil)
		require.NoError(t, err)
		want := []string{
			"package5-1.5.1",
			"locked-dep-2.0.0",
		}
		require.Equal(t, len(install), len(want))
		for i := range install {
			got := install[i].Name + "-" + install[i].Version
			require.Equal(t, got, want[i])
		}
	})
	t.Run("stricter requirement wins", func(t *testing.T) {
		_, index := testGetPackagesAndIndex()
		resolver := NewPkgResolver(context.Background(), testNamedRepositoryFromIndexes(index))
		names := []string{"package5>1.0.0", "package5=1.5.1"}
		sort.Strings(names)
		install, _, err := resolver.GetPackagesWithDependencies(context.Background(), names, nil)
		require.NoError(t, err)
		want := []string{
			"package5-1.5.1",
		}
		require.Equal(t, len(install), len(want))
		for i := range install {
			got := install[i].Name + "-" + install[i].Version
			require.Equal(t, want[i], got)
		}
	})
	t.Run("conflicting requirements", func(t *testing.T) {
		_, index := testGetPackagesAndIndex()
		resolver := NewPkgResolver(context.Background(), testNamedRepositoryFromIndexes(index))
		names := []string{"package5=1.0.0", "package5=1.5.1"}
		sort.Strings(names)
		_, _, err := resolver.GetPackagesWithDependencies(context.Background(), names, nil)
		require.Error(t, err, "Packages should conflict")
	})
}

func TestGetPackageDependencies(t *testing.T) {
	t.Run("normal dependencies", func(t *testing.T) {
		// getPackageDependencies does not get the same dependencies twice.
		expected := []string{"dep4", "dep5", "dep1", "busybox", "foo", "dep6", "libq", "dep3", "dep2"}
		_, index := testGetPackagesAndIndex()

		resolver := NewPkgResolver(context.Background(), testNamedRepositoryFromIndexes(index))
		_, pkgs, _, err := resolver.GetPackageWithDependencies(context.Background(), "package1", nil, map[*RepositoryPackage]string{})
		require.NoErrorf(t, err, "unable to get dependencies")

		actual := make([]string, 0, len(pkgs))
		for _, p := range pkgs {
			actual = append(actual, p.Name)
		}
		require.True(t, reflect.DeepEqual(expected, actual), "dependencies mismatch:\nactual %v\nexpect %v", actual, expected)
	})
	t.Run("circular dependencies", func(t *testing.T) {
		// getPackageDependencies does not get the same dependencies twice.
		expected := []string{"dep8"}
		_, index := testGetPackagesAndIndex()

		resolver := NewPkgResolver(context.Background(), testNamedRepositoryFromIndexes(index))
		_, pkgs, _, err := resolver.GetPackageWithDependencies(context.Background(), "package3", nil, map[*RepositoryPackage]string{})
		require.NoErrorf(t, err, "unable to get dependencies")

		actual := make([]string, 0, len(pkgs))
		for _, p := range pkgs {
			actual = append(actual, p.Name)
		}
		require.True(t, reflect.DeepEqual(expected, actual), "dependencies mismatch:\nactual %v\nexpect %v", actual, expected)
	})
	t.Run("existing dependency", func(t *testing.T) {
		origPkgs, index := testGetPackagesAndIndex()
		resolver := NewPkgResolver(context.Background(), testNamedRepositoryFromIndexes(index))

		// start with regular resolution, just to compare
		expectedName := "package5"
		expectedVersion := "2.0.0" // highest version
		_, pkgs, _, err := resolver.GetPackageWithDependencies(context.Background(), "package9", nil, map[*RepositoryPackage]string{})
		require.NoErrorf(t, err, "unable to get dependencies")
		require.Len(t, pkgs, 1, "package9 should have one dependency, %s", expectedName)
		require.Equal(t, expectedName, pkgs[0].Name)
		require.Equal(t, expectedVersion, pkgs[0].Version)

		// now make something pre-existing
		expectedName = "package5-special"
		expectedVersion = "1.2.0" // lower version than the highest
		existingPkgs := make(map[string]*RepositoryPackage)
		for _, p := range origPkgs {
			if p.Name == expectedName && p.Version == expectedVersion {
				existingPkgs[p.Name] = p
				break
			}
		}
		_, pkgs, _, err = resolver.GetPackageWithDependencies(context.Background(), "package9", existingPkgs, map[*RepositoryPackage]string{})
		require.NoErrorf(t, err, "unable to get dependencies")
		require.Len(t, pkgs, 1, "package9 should have one dependency, %s", expectedName)
		require.Equal(t, expectedName, pkgs[0].Name)
		require.Equal(t, expectedVersion, pkgs[0].Version)
	})
}

func TestResolvePackage(t *testing.T) {
	t.Run("no match", func(t *testing.T) {
		// getPackageDependencies does not get the same dependencies twice.
		_, index := testGetPackagesAndIndex()

		resolver := NewPkgResolver(context.Background(), testNamedRepositoryFromIndexes(index))
		pkgs, err := resolver.ResolvePackage("package12", map[*RepositoryPackage]string{})
		require.Error(t, err)
		require.Len(t, pkgs, 0)
	})
	t.Run("any version", func(t *testing.T) {
		// getPackageDependencies does not get the same dependencies twice.
		_, index := testGetPackagesAndIndex()

		resolver := NewPkgResolver(context.Background(), testNamedRepositoryFromIndexes(index))
		pkgs, err := resolver.ResolvePackage("package5", map[*RepositoryPackage]string{})
		require.NoError(t, err)
		require.Len(t, pkgs, 7)
	})
	t.Run("specific version", func(t *testing.T) {
		// getPackageDependencies does not get the same dependencies twice.
		_, index := testGetPackagesAndIndex()

		resolver := NewPkgResolver(context.Background(), testNamedRepositoryFromIndexes(index))
		version := "1.0.0"
		pkgs, err := resolver.ResolvePackage("package5="+version, map[*RepositoryPackage]string{})
		require.NoError(t, err)
		require.Len(t, pkgs, 1)
		require.Equal(t, version, pkgs[0].Version)

		// and now one that does not exist
		version = "1.0.1"
		pkgs, err = resolver.ResolvePackage("package5="+version, map[*RepositoryPackage]string{})
		require.Error(t, err, "package5 version 1.0.1 does not exist")
		require.Len(t, pkgs, 0)
	})
	t.Run("greater than version", func(t *testing.T) {
		// getPackageDependencies does not get the same dependencies twice.
		_, index := testGetPackagesAndIndex()

		resolver := NewPkgResolver(context.Background(), testNamedRepositoryFromIndexes(index))
		pkgs, err := resolver.ResolvePackage("package5>1.0.0", map[*RepositoryPackage]string{})
		require.NoError(t, err)
		require.Len(t, pkgs, 6)
		// first version should be highest match
		require.Equal(t, "2.0.0", pkgs[0].Version)
	})
	t.Run("with provides", func(t *testing.T) {
		// getPackageDependencies does not get the same dependencies twice.
		_, index := testGetPackagesAndIndex()

		resolver := NewPkgResolver(context.Background(), testNamedRepositoryFromIndexes(index))
		pkgs, err := resolver.ResolvePackage("package7", map[*RepositoryPackage]string{})
		require.NoError(t, err)
		require.Len(t, pkgs, 2)
		// first version should be highest match
		require.Equal(t, "1", pkgs[0].Version)
	})
}

// Make sure that all versions exist
func TestVersionHierarchy(t *testing.T) {
	repo := Repository{}
	index := repo.WithIndex(&APKIndex{
		Packages: []*Package{
			{Name: "multi-versioner", Version: "1.2.3-r0"},
			{Name: "multi-versioner", Version: "1.3.6-r0"},
			{Name: "multi-versioner", Version: "1.2.8-r0"},
			{Name: "multi-versioner", Version: "1.7.1-r0"},
			{Name: "multi-versioner", Version: "1.7.1-r1"},
			{Name: "multi-versioner", Version: "2.0.6-r0"},
		},
	})
	resolver := NewPkgResolver(context.Background(), testNamedRepositoryFromIndexes([]*RepositoryWithIndex{index}))
	pkgWithVersions, ok := resolver.nameMap["multi-versioner"]
	require.True(t, ok, "found multi-versioner in nameMap")
	for i, pkg := range pkgWithVersions {
		require.True(t, pkg.Version == index.Packages()[i].Version, "multi-versioner has version")
	}
}

func TestSortPackages(t *testing.T) {
	// we are not looking for a whole dependency graph; just for the specific tests we want
	// around resolving dependency A vs B
	type repoPkgBase struct {
		pkg   *Package
		repo  string
		order int
	}
	tests := []struct {
		name     string
		pkgs     []repoPkgBase
		compare  *repoPkgBase
		existing []repoPkgBase
	}{
		{"just versions", []repoPkgBase{
			{&Package{Name: "package1", Version: "1.0.0"}, "http://a.b.com", 2},
			{&Package{Name: "package1", Version: "2.0.1"}, "http://a.b.com", 0},
			{&Package{Name: "package1", Version: "1.2.0abc"}, "http://a.b.com", 3},
			{&Package{Name: "package1", Version: "1.2.0"}, "http://a.b.com", 1},
		}, nil, nil},
		{"just names", []repoPkgBase{
			{&Package{Name: "package1", Version: "1.0.0"}, "http://a.b.com", 1},
			{&Package{Name: "package2", Version: "1.0.0"}, "http://a.b.com", 2},
			{&Package{Name: "earlier", Version: "1.0.0"}, "http://a.b.com", 0},
		}, nil, nil},
		{"just origins", []repoPkgBase{
			{&Package{Name: "package1", Version: "1.0.0", Origin: "c"}, "http://a.b.com", 2},
			{&Package{Name: "package1", Version: "2.0.1", Origin: "b"}, "http://a.b.com", 1},
			{&Package{Name: "package1", Version: "1.2.0", Origin: "a"}, "http://a.b.com", 0},
		}, &repoPkgBase{&Package{Origin: "a"}, "", 0}, nil},
		{"just repositories", []repoPkgBase{
			{&Package{Name: "package1", Version: "1.0.0", Origin: "c"}, "http://other.com", 2},
			{&Package{Name: "package1", Version: "2.0.1", Origin: "b"}, "http://example.com", 1},
			{&Package{Name: "package1", Version: "1.2.0", Origin: "a"}, "http://a.b.com", 0},
		}, &repoPkgBase{&Package{Origin: "a"}, "http://a.b.com", 0}, nil},
		{"just existing", []repoPkgBase{
			{&Package{Name: "package1", Version: "1.0.0", Origin: "c"}, "http://other.com", 0},
			{&Package{Name: "package1", Version: "2.0.1", Origin: "b"}, "http://example.com", 1},
			{&Package{Name: "package1", Version: "1.2.0", Origin: "a"}, "http://a.b.com", 2},
		}, nil, []repoPkgBase{
			{&Package{Name: "package1", Version: "1.0.0", Origin: "c"}, "http://other.com", 0},
		}},
		{"origins and versions", []repoPkgBase{
			{&Package{Name: "package1", Version: "1.0.0", Origin: "a"}, "http://a.b.com", 1},
			{&Package{Name: "package1", Version: "2.0.1", Origin: "b"}, "http://a.b.com", 2},
			{&Package{Name: "package1", Version: "1.2.0", Origin: "a"}, "http://a.b.com", 0},
		}, &repoPkgBase{&Package{Origin: "a"}, "", 0}, nil},
		{"origins and repositories and versions", []repoPkgBase{
			{&Package{Name: "package1", Version: "1.0.0", Origin: "a"}, "http://a.b.com", 1},
			{&Package{Name: "package1", Version: "2.0.1", Origin: "b"}, "http://other.com", 4},
			{&Package{Name: "package1", Version: "2.0.0", Origin: "b"}, "http://other.com", 5},
			{&Package{Name: "package1", Version: "1.0.0", Origin: "c"}, "http://a.b.com", 2},
			{&Package{Name: "package1", Version: "1.2.0", Origin: "a"}, "http://example.com", 3},
			{&Package{Name: "package1", Version: "1.2.0", Origin: "a"}, "http://a.b.com", 0},
		}, &repoPkgBase{&Package{Origin: "a"}, "http://a.b.com", 0}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				pkgs            []*RepositoryPackage
				pkg             *RepositoryPackage
				existing        = map[string]*RepositoryPackage{}
				existingOrigins = map[string]map[string]bool{}
			)
			for _, pkg := range tt.pkgs {
				// we cheat and use the InstalledSize for the preferred order, so that it gets carried around.
				// this only works because the sorting algorithm does not look at or depend upon InstalledSize.
				// if we ever change that, we'll need to change this test.
				pkg.pkg.InstalledSize = uint64(pkg.order)
				pkgs = append(pkgs, NewRepositoryPackage(pkg.pkg, &RepositoryWithIndex{Repository: &Repository{URI: pkg.repo}}))
			}
			if tt.compare != nil {
				pkg = NewRepositoryPackage(tt.compare.pkg, &RepositoryWithIndex{Repository: &Repository{URI: tt.compare.repo}})
			}
			for _, pkg := range tt.existing {
				existing[pkg.pkg.Name] = NewRepositoryPackage(pkg.pkg, &RepositoryWithIndex{Repository: &Repository{URI: pkg.repo}})
				addExistingOrigin(existingOrigins, pkg.pkg.Origin, pkg.pkg.Version)
			}
			namedPkgs := testNamedPackageFromPackages(pkgs)
			pr := NewPkgResolver(context.Background(), []NamedIndex{})
			pr.sortPackages(namedPkgs, pkg, "", existing, existingOrigins, "")
			for i, pkg := range namedPkgs {
				require.Equal(t, int(pkg.InstalledSize), i, "position matches")
			}
		})
	}
}

func TestExcludedDeps(t *testing.T) {
	providers := map[string][]string{
		"musl=1.23-r4":      {"so:ld-linux-aarch64.so.1"},
		"ld-linux=2.38-r10": {"so:ld-linux-aarch64.so.1"},
	}
	dependers := map[string][]string{
		"glibc=2.38-r10": {"!musl", "so:ld-linux-aarch64.so.1"},
	}

	resolver := makeResolver(providers, dependers)
	pkgs, conflicts, err := resolver.GetPackagesWithDependencies(context.Background(), []string{"glibc"}, nil)
	require.NoError(t, err)

	wantPkgs := []string{
		"ld-linux-2.38-r10.apk",
		"glibc-2.38-r10.apk",
	}
	wantConflicts := []string{"musl"}

	require.Equal(t, conflicts, wantConflicts)

	require.Len(t, pkgs, len(wantPkgs))
	for i, pkg := range pkgs {
		require.Equal(t, pkg.Filename(), wantPkgs[i])
	}
}

func TestSameProvidedVersion(t *testing.T) {
	providers := map[string][]string{
		"ld-linux=2.38-r10": {"so:ld-linux-aarch64.so.1=1.0"},
		"ld-linux=2.38-r11": {"so:ld-linux-aarch64.so.1=1.0"},
	}
	dependers := map[string][]string{
		"glibc=2.38-r10": {"so:ld-linux-aarch64.so.1"},
	}

	resolver := makeResolver(providers, dependers)
	pkgs, _, err := resolver.GetPackagesWithDependencies(context.Background(), []string{"glibc"}, nil)
	require.NoError(t, err)

	// When two options provide the same version of a virtual, we expect to take the higher version package.
	wantPkgs := []string{
		"ld-linux-2.38-r11.apk",
		"glibc-2.38-r10.apk",
	}

	require.Len(t, pkgs, len(wantPkgs))
	for i, pkg := range pkgs {
		require.Equal(t, pkg.Filename(), wantPkgs[i])
	}
}

// If a package has a provides with a different version than the real
// package (here libcurl-openssl4=8.12.1-r1 provides libcurl-abi=8.12.1),
// both should be allowed in the same DAG
func TestDepWithProvidesOfDiffVersion(t *testing.T) {
	providers := map[string][]string{
		"libcurl-openssl4=8.12.1-r1": {
			"libcurl-abi=8.12.1", "so:libcurl.so.4=4",
		},
	}
	dependers := map[string][]string{
		"foo=1":                      {}, // an extra dep level needed to trigger bug
		"libcurl-openssl4=8.12.1-r1": {"foo"},
		"curl=8.12.1-r1":             {"libcurl-abi=8.12.1", "so:libcurl.so.4"},
		"curl-dev=8.12.1-r1":         {"so:libcurl.so.4"},
	}

	resolver := makeResolver(providers, dependers)
	pkgs, _, err := resolver.GetPackagesWithDependencies(context.Background(), []string{"curl-dev", "curl"}, nil)
	require.NoError(t, err)

	wantPkgs := []string{
		"foo-1.apk",
		"libcurl-openssl4-8.12.1-r1.apk",
		"curl-dev-8.12.1-r1.apk",
		"curl-8.12.1-r1.apk",
	}

	require.Len(t, pkgs, len(wantPkgs))
	for i, pkg := range pkgs {
		require.Equal(t, pkg.Filename(), wantPkgs[i])
	}
}

func TestHigherProvidedVersion(t *testing.T) {
	providers := map[string][]string{
		"ld-linux=2.38-r10": {"so:ld-linux-aarch64.so.1=1.1"},
		"ld-linux=2.38-r11": {"so:ld-linux-aarch64.so.1=1.0"},
	}
	dependers := map[string][]string{
		"glibc=2.38-r10": {"so:ld-linux-aarch64.so.1"},
	}

	resolver := makeResolver(providers, dependers)
	pkgs, _, err := resolver.GetPackagesWithDependencies(context.Background(), []string{"glibc"}, nil)
	require.NoError(t, err)

	// When two options provide the different versions of a virtual, we expect to take the higher virtual version.
	wantPkgs := []string{
		"ld-linux-2.38-r10.apk",
		"glibc-2.38-r10.apk",
	}

	require.Len(t, pkgs, len(wantPkgs))
	for i, pkg := range pkgs {
		require.Equal(t, pkg.Filename(), wantPkgs[i])
	}
}

func TestConstrains(t *testing.T) {
	providers := map[string][]string{
		"ld-linux=2.38-r10": {"so:ld-linux-aarch64.so.1=1.0"},
		"ld-linux=2.38-r11": {"so:ld-linux-aarch64.so.1=1.1"},
	}
	dependers := map[string][]string{
		"glibc=2.38-r10": {"so:ld-linux-aarch64.so.1=1.0"},
		"glibc=2.39-r0":  {"so:ld-linux-aarch64.so.1"},
		"foo=1.23-r4":    {"so:ld-linux-aarch64.so.1"},
	}

	resolver := makeResolver(providers, dependers)
	pkgs, _, err := resolver.GetPackagesWithDependencies(context.Background(), []string{"glibc~2.38", "foo"}, nil)
	require.NoError(t, err)

	// We expect to get the r10 of ld-linux because glibc~2.38 should constraint the solution to that, even though "foo" doesn't care.
	wantPkgs := []string{
		"ld-linux-2.38-r10.apk",
		"glibc-2.38-r10.apk",
		"foo-1.23-r4.apk",
	}

	require.Len(t, pkgs, len(wantPkgs))
	for i, pkg := range pkgs {
		require.Equal(t, pkg.Filename(), wantPkgs[i])
	}
}

func testNamedRepositoryFromIndexes(indexes []*RepositoryWithIndex) (named []NamedIndex) {
	for _, index := range indexes {
		named = append(named, NewNamedRepositoryWithIndex("", index))
	}
	return
}

func testNamedPackageFromPackages(pkgs []*RepositoryPackage) (named []*repositoryPackage) {
	for _, pkg := range pkgs {
		named = append(named, &repositoryPackage{RepositoryPackage: pkg})
	}
	return
}

func testNamedPackageFromVersionAndPin(version, pin string) *repositoryPackage {
	rp := NewRepositoryPackage(
		&Package{Version: version},
		&RepositoryWithIndex{
			Repository: &Repository{URI: "local"},
		},
	)
	return &repositoryPackage{
		RepositoryPackage: rp,
		pinnedName:        pin,
	}
}

func makeResolver(provs, deps map[string][]string) *PkgResolver {
	packages := make(map[string]*Package, max(len(provs), len(deps)))

	for pkgver := range provs {
		parsed := ResolvePackageNameVersionPin(pkgver)
		packages[pkgver] = &Package{Name: parsed.Name, Version: parsed.Version}
	}
	for pkgver := range deps {
		parsed := ResolvePackageNameVersionPin(pkgver)
		packages[pkgver] = &Package{Name: parsed.Name, Version: parsed.Version}
	}

	for pkgver, pkgProvs := range provs {
		packages[pkgver].Provides = pkgProvs
	}
	for pkgver, pkgDeps := range deps {
		packages[pkgver].Dependencies = pkgDeps
	}

	repo := Repository{}
	repoWithIndex := repo.WithIndex(&APKIndex{
		Packages: slices.Collect(maps.Values(packages)),
	})
	return NewPkgResolver(context.Background(), testNamedRepositoryFromIndexes([]*RepositoryWithIndex{repoWithIndex}))
}

func TestDisqualifyingOtherArchitectures(t *testing.T) {
	names := []string{"package1", "package2", "onlyinarm64"}
	_, index := testGetPackagesAndIndex()

	arm64 := slices.Clone(index)
	repo := Repository{}
	repoWithIndex := repo.WithIndex(&APKIndex{
		Packages: []*Package{{Name: "onlyinarm64", Version: "1.0.0"}},
	})
	arm64 = append(arm64, repoWithIndex)

	armIndex := testNamedRepositoryFromIndexes(arm64)

	byArch := map[string][]NamedIndex{
		"x86_64":  testNamedRepositoryFromIndexes(index),
		"aarch64": armIndex,
	}

	resolver := NewPkgResolver(context.Background(), armIndex)
	_, _, err := resolver.GetPackagesWithDependencies(context.Background(), names, byArch)
	require.ErrorContains(t, err, "package \"onlyinarm64-1.0.0.apk\" not available for arch \"x86_64\"")
}

// TestVirtualProviderBacktracking is the canonical cross-package backtracking case.
// pkg-a needs a virtual with any version; pkg-b needs the same virtual at exactly 1.0.
// The greedy resolver would pick provider-new (v2.0) for pkg-a, disqualify provider-old,
// and then fail to satisfy pkg-b's virt=1.0 requirement.
// The pre-constrain step should prevent that by DQing provider-new before Phase 1 runs.
func TestVirtualProviderBacktracking(t *testing.T) {
	providers := map[string][]string{
		"provider-new=2.0": {"virt=2.0"},
		"provider-old=1.0": {"virt=1.0"},
	}
	dependers := map[string][]string{
		"pkg-a=1.0": {"virt"},
		"pkg-b=1.0": {"virt=1.0"},
	}
	resolver := makeResolver(providers, dependers)
	pkgs, _, err := resolver.GetPackagesWithDependencies(
		context.Background(), []string{"pkg-a", "pkg-b"}, nil)
	require.NoError(t, err)

	names := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		names = append(names, p.Filename())
	}
	require.Contains(t, names, "provider-old-1.0.apk")
	require.Contains(t, names, "pkg-a-1.0.apk")
	require.Contains(t, names, "pkg-b-1.0.apk")
	require.NotContains(t, names, "provider-new-2.0.apk")
}

// TestLevel1Backtracking checks that within a single top-level package's dep subtree,
// a greedy provider choice that causes a downstream conflict is retried with the
// next candidate.
//
// consumer depends on "lib" (any version) and "sibling".
// sibling depends on "lib=1.0".
// lib-high=2.0 provides lib=2.0; lib-low=1.0 provides lib=1.0.
// The greedy resolver picks lib-high first; sibling then can't satisfy lib=1.0.
// With Level 1 backtracking the resolver retries with lib-low.
func TestLevel1Backtracking(t *testing.T) {
	providers := map[string][]string{
		"lib-high=2.0": {"lib=2.0"},
		"lib-low=1.0":  {"lib=1.0"},
	}
	dependers := map[string][]string{
		"consumer=1.0": {"lib", "sibling"},
		"sibling=1.0":  {"lib=1.0"},
	}
	resolver := makeResolver(providers, dependers)
	pkgs, _, err := resolver.GetPackagesWithDependencies(
		context.Background(), []string{"consumer"}, nil)
	require.NoError(t, err)

	names := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		names = append(names, p.Filename())
	}
	require.Contains(t, names, "lib-low-1.0.apk")
	require.Contains(t, names, "sibling-1.0.apk")
	require.Contains(t, names, "consumer-1.0.apk")
	require.NotContains(t, names, "lib-high-2.0.apk")
}

// TestTransitiveVirtualProviderBacktracking is a deeper version of
// TestVirtualProviderBacktracking. The versioned constraint on the virtual
// comes through a transitive dependency (A → libfoo any; B → C → libfoo=1.5),
// so the Level 2 pre-constrain step (which only looks at direct deps) is not
// sufficient. The Phase 2 retry mechanism must kick in: when B's resolution
// fails because A already committed to libfoo-new, Phase 2 reorders to process
// B first so its transitive constraint (libfoo=1.5 via C) disqualifies
// libfoo-new before A selects a provider.
func TestTransitiveVirtualProviderBacktracking(t *testing.T) {
	providers := map[string][]string{
		"libfoo-new=2.0": {"libfoo=2.0"},
		"libfoo-old=1.5": {"libfoo=1.5"},
	}
	dependers := map[string][]string{
		"pkg-a=1.0": {"libfoo"},
		"pkg-b=1.0": {"pkg-c"},
		"pkg-c=1.0": {"libfoo=1.5"},
	}
	resolver := makeResolver(providers, dependers)
	pkgs, _, err := resolver.GetPackagesWithDependencies(
		context.Background(), []string{"pkg-a", "pkg-b"}, nil)
	require.NoError(t, err)

	names := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		names = append(names, p.Filename())
	}
	require.Contains(t, names, "libfoo-old-1.5.apk")
	require.Contains(t, names, "pkg-a-1.0.apk")
	require.Contains(t, names, "pkg-b-1.0.apk")
	require.Contains(t, names, "pkg-c-1.0.apk")
	require.NotContains(t, names, "libfoo-new-2.0.apk")
}

// TestHardErrorNotRetried verifies that a hard failure ("nothing provides X")
// is not swallowed by backtracking and surfaces as an error.
func TestHardErrorNotRetried(t *testing.T) {
	dependers := map[string][]string{
		"pkg=1.0": {"nonexistent"},
	}
	resolver := makeResolver(nil, dependers)
	_, _, err := resolver.GetPackagesWithDependencies(
		context.Background(), []string{"pkg"}, nil)
	require.Error(t, err)
	require.ErrorContains(t, err, "nonexistent")
}

// TestNonRetryableErrorInCandidateLoop verifies that a hard (non-retryable)
// error returned from a candidate's subtree propagates immediately and does
// NOT cause the resolver to fall back to the next candidate.
//
// provider-high=2.0 is tried first (higher version). It depends on "ghost"
// which is absent from all indexes — a hard "nothing provides" error.
// provider-low=1.0 would succeed, but it must NOT be tried.
func TestNonRetryableErrorInCandidateLoop(t *testing.T) {
	providers := map[string][]string{
		"provider-high=2.0": {"virt=2.0"},
		"provider-low=1.0":  {"virt=1.0"},
	}
	dependers := map[string][]string{
		"provider-high=2.0": {"ghost"}, // hard dep on a package that does not exist
		"pkg=1.0":           {"virt"},
	}
	resolver := makeResolver(providers, dependers)
	_, _, err := resolver.GetPackagesWithDependencies(
		context.Background(), []string{"pkg"}, nil)
	// Must get an error; if provider-low were tried the call would succeed.
	require.Error(t, err)
	require.ErrorContains(t, err, "ghost")
}

// TestLevel1CandidateRetryOnRetryableError is the purest Level 1 backtracking
// test: the candidate loop in getPackageDependencies tries the best candidate
// first, discovers a retryable failure, restores the snapshot, and succeeds
// with the next candidate.
//
// virt-a=2.0 provides both "virt=2.0" and "helper=2.0".
// When virt-a is chosen, disqualifyConflicts DQs provider-sub because
// provider-sub provides "helper=1.0" which conflicts with "helper=2.0".
// virt-a depends on "sub-pkg", the sole provider of which is provider-sub —
// now disqualified — so getPackageDependencies(virt-a) fails retryably.
// The snapshot is restored (un-DQing provider-sub) and virt-b=1.0 is tried.
// virt-b provides only "virt=1.0" and has no deps, so it resolves cleanly.
func TestLevel1CandidateRetryOnRetryableError(t *testing.T) {
	providers := map[string][]string{
		"virt-a=2.0":       {"virt=2.0", "helper=2.0"},
		"virt-b=1.0":       {"virt=1.0"},
		"provider-sub=1.0": {"sub-pkg=1.0", "helper=1.0"},
	}
	dependers := map[string][]string{
		"virt-a=2.0": {"sub-pkg"}, // needs sub-pkg, only available via provider-sub
		"pkg=1.0":    {"virt"},
	}
	resolver := makeResolver(providers, dependers)
	pkgs, _, err := resolver.GetPackagesWithDependencies(
		context.Background(), []string{"pkg"}, nil)
	require.NoError(t, err)

	names := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		names = append(names, p.Filename())
	}
	// virt-b should be selected (virt-a's subtree failed retryably → backtracked)
	require.Contains(t, names, "virt-b-1.0.apk")
	require.Contains(t, names, "pkg-1.0.apk")
	require.NotContains(t, names, "virt-a-2.0.apk")
	require.NotContains(t, names, "provider-sub-1.0.apk")
}

// TestAllCandidatesRetryablyFail exercises the !succeeded branch of the
// candidate loop: all providers of a dep fail retryably, so the resolver
// returns an error rather than a spurious success.
//
// Both virt-a and virt-b depend on "helper=5.0". Only helper=1.0 exists, so
// constrain DQs it and filterPackages returns empty for each candidate's
// subtree — a retryable (DQ-based) failure. After exhausting both candidates,
// getPackageDependencies returns an error.
func TestAllCandidatesRetryablyFail(t *testing.T) {
	providers := map[string][]string{
		"virt-a=2.0": {"virt=2.0"},
		"virt-b=1.0": {"virt=1.0"},
	}
	dependers := map[string][]string{
		"virt-a=2.0": {"helper=5.0"}, // requires helper=5.0 which cannot be satisfied
		"virt-b=1.0": {"helper=5.0"},
		"helper=1.0": {}, // only version 1.0 exists; does not satisfy =5.0
		"pkg=1.0":    {"virt"},
	}
	resolver := makeResolver(providers, dependers)
	_, _, err := resolver.GetPackagesWithDependencies(
		context.Background(), []string{"pkg"}, nil)
	require.Error(t, err)
}

// TestGenuineConflictExhaustsRetries verifies that when two top-level packages
// have genuinely conflicting version requirements that no package ordering can
// resolve, the Phase 2 retry mechanism exhausts all attempts and returns an error.
//
// pkg-x requires virt=2.0; pkg-y requires virt=1.0. The pre-constrain step DQs
// both providers (provider-a is DQed by "virt=1.0"; provider-b is DQed by
// "virt=2.0"), so no ordering of pkg-x and pkg-y will ever succeed.
// After len(packages) retry attempts, lastPhase2Err is returned.
func TestGenuineConflictExhaustsRetries(t *testing.T) {
	providers := map[string][]string{
		"provider-a=2.0": {"virt=2.0"},
		"provider-b=1.0": {"virt=1.0"},
	}
	dependers := map[string][]string{
		"pkg-x=1.0": {"virt=2.0"},
		"pkg-y=1.0": {"virt=1.0"},
	}
	resolver := makeResolver(providers, dependers)
	_, _, err := resolver.GetPackagesWithDependencies(
		context.Background(), []string{"pkg-x", "pkg-y"}, nil)
	require.Error(t, err)
}

// TestSameVersionProvideDoesNotConflict is a regression test for the
// conflictingVersion fix.  Two packages both advertising the same versioned
// virtual ("helper=1.0") must NOT disqualify each other: co-providing the same
// virtual at the same version is harmless when no package actually depends on
// it.  Previously, the early-return `if constraint.Version != "" { return true
// }` in conflictingVersion caused disqualifyConflicts to DQ helper-lib-direct
// the moment pkg-b was resolved in Phase 1, making the whole install fail.
func TestSameVersionProvideDoesNotConflict(t *testing.T) {
	providers := map[string][]string{
		"helper-lib-direct=1.0": {"helper=1.0"},
		"pkg-b=1.0":             {"helper=1.0"}, // same version — must not DQ helper-lib-direct
	}
	dependers := map[string][]string{
		"helper-lib-direct=1.0": {"stub"},
		"pkg-a=1.0":             {"helper-lib-direct"},
		"pkg-b=1.0":             {"sub-dep"},
		"stub=1.0":              {},
		"sub-dep=1.0":           {},
	}
	resolver := makeResolver(providers, dependers)
	pkgs, _, err := resolver.GetPackagesWithDependencies(
		context.Background(), []string{"pkg-a", "pkg-b"}, nil)
	require.NoError(t, err)
	names := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		names = append(names, p.Filename())
	}
	require.Contains(t, names, "pkg-a-1.0.apk")
	require.Contains(t, names, "pkg-b-1.0.apk")
	require.Contains(t, names, "helper-lib-direct-1.0.apk")
	require.Contains(t, names, "sub-dep-1.0.apk")
}

// TestTransitiveLibfooBacktracking exercises a four-package scenario where the
// versioned constraint on "libfoo" is two levels deep in the dependency graph.
//
// Top-level: pkg-a, pkg-b, pkg-c
//   - pkg-a depends on "libfoo" (any version)
//   - pkg-b has no dependencies
//   - pkg-c depends on pkg-d
//   - pkg-d depends on "libfoo=1.5" (versioned)
//
// Candidates: libfoo-new=2.0 (provides libfoo=2.0), libfoo-old=1.5 (provides libfoo=1.5).
// Without backtracking the greedy resolver would pick libfoo-new first and
// then fail when pkg-d requests libfoo=1.5. With backtracking it retries and
// selects libfoo-old=1.5, satisfying both pkg-a and pkg-d.
func TestTransitiveLibfooBacktracking(t *testing.T) {
	providers := map[string][]string{
		"libfoo-new=2.0": {"libfoo=2.0"},
		"libfoo-old=1.5": {"libfoo=1.5"},
	}
	dependers := map[string][]string{
		"pkg-a=1.0": {"libfoo"},
		"pkg-b=1.0": {},
		"pkg-c=1.0": {"pkg-d"},
		"pkg-d=1.0": {"libfoo=1.5"},
	}
	resolver := makeResolver(providers, dependers)
	pkgs, _, err := resolver.GetPackagesWithDependencies(
		context.Background(), []string{"pkg-a", "pkg-b", "pkg-c"}, nil)
	require.NoError(t, err)

	names := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		names = append(names, p.Filename())
	}
	require.Contains(t, names, "libfoo-old-1.5.apk")
	require.Contains(t, names, "pkg-a-1.0.apk")
	require.Contains(t, names, "pkg-b-1.0.apk")
	require.Contains(t, names, "pkg-c-1.0.apk")
	require.Contains(t, names, "pkg-d-1.0.apk")
	require.NotContains(t, names, "libfoo-new-2.0.apk")
}

// TestThreeProvidersOneUnversionedSelectsHighest verifies that when three
// packages provide the same virtual — one without a version in its provides
// line and two with explicit versioned provides — the resolver installs only
// the package that advertises the highest version of the virtual.
//
// provider-unversioned=1.0  provides "virt"      (no explicit version)
// provider-mid=2.0          provides "virt=2.0"  (versioned, lower)
// provider-high=3.0         provides "virt=3.0"  (versioned, highest)
//
// A consumer depending on "virt" (any version) must resolve to provider-high
// because its provided virtual version (3.0) ranks above 2.0 and above 1.0
// (the package-version fallback used for the unversioned provide). The other
// two providers must not appear in the final install set.
func TestThreeProvidersOneUnversionedSelectsHighest(t *testing.T) {
	providers := map[string][]string{
		"provider-unversioned=1.0": {"virt"},     // unversioned provide; effective virt version = 1.0
		"provider-mid=2.0":         {"virt=2.0"}, // versioned, lower
		"provider-high=3.0":        {"virt=3.0"}, // versioned, highest
	}
	dependers := map[string][]string{
		"consumer=1.0": {"virt"},
	}
	resolver := makeResolver(providers, dependers)
	pkgs, _, err := resolver.GetPackagesWithDependencies(
		context.Background(), []string{"consumer"}, nil)
	require.NoError(t, err)

	names := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		names = append(names, p.Filename())
	}
	require.Contains(t, names, "consumer-1.0.apk")
	require.Contains(t, names, "provider-high-3.0.apk")
	require.NotContains(t, names, "provider-mid-2.0.apk")
	require.NotContains(t, names, "provider-unversioned-1.0.apk")
}

// TestSameOriginVersionPreferredOverNewer is a unit test for the sort tier that
// prefers an exact origin+version match over a newer package from the same origin.
//
// Two candidates both provide "libpq" and share origin "postgresql":
//   - libpq-15=15.3-r1: exact version match with the already-selected postgresql-15=15.3-r1
//   - libpq-15=15.4-r0: newer version, same origin, no exact match
//
// Without the new tier the greedy version sort would pick 15.4-r0 (higher version).
// With the new tier 15.3-r1 must sort first.
func TestSameOriginVersionPreferredOverNewer(t *testing.T) {
	const origin = "postgresql"
	const selectedVersion = "15.3-r1"

	// Two candidates for virtual "libpq", both from origin "postgresql".
	matchedPkg := NewRepositoryPackage(
		&Package{Name: "libpq-15", Version: selectedVersion, Origin: origin},
		&RepositoryWithIndex{Repository: &Repository{URI: "http://repo"}},
	)
	newerPkg := NewRepositoryPackage(
		&Package{Name: "libpq-15", Version: "15.4-r0", Origin: origin},
		&RepositoryWithIndex{Repository: &Repository{URI: "http://repo"}},
	)

	// Simulate postgresql-15=15.3-r1 already being in the install set.
	existingOrigins := map[string]map[string]bool{}
	addExistingOrigin(existingOrigins, origin, selectedVersion)

	candidates := testNamedPackageFromPackages([]*RepositoryPackage{newerPkg, matchedPkg})
	pr := NewPkgResolver(context.Background(), []NamedIndex{})
	pr.sortPackages(candidates, nil, "libpq", map[string]*RepositoryPackage{}, existingOrigins, "")

	// The version-matched candidate must rank first.
	require.Equal(t, selectedVersion, candidates[0].Version,
		"exact origin+version match should rank before newer package from same origin")
}

// TestSameOriginVersionEndToEnd exercises the full resolver flow: postgresql-15 is
// a top-level package that gets resolved before pkg-b, so its origin+version end up
// in existingOrigins when libpq providers are sorted for pkg-b's dependency.
//
// Two libpq providers share origin "postgresql":
//   - libpq-15=15.3-r1 (same version as postgresql-15) — must be selected
//   - libpq-15=15.4-r0 (newer)                          — must not be selected
func TestSameOriginVersionEndToEnd(t *testing.T) {
	const origin = "postgresql"

	// Build packages manually so we can set the Origin field.
	allPkgs := []*Package{
		{Name: "postgresql-15", Version: "15.3-r1", Origin: origin},
		{Name: "libpq-15", Version: "15.3-r1", Origin: origin, Provides: []string{"libpq=1"}},
		{Name: "libpq-15", Version: "15.4-r0", Origin: origin, Provides: []string{"libpq=1"}},
		{Name: "pkg-a", Version: "1.0", Dependencies: []string{"postgresql-15"}},
		{Name: "pkg-b", Version: "1.0", Dependencies: []string{"libpq"}},
	}
	repo := Repository{}
	repoWithIndex := repo.WithIndex(&APKIndex{Packages: allPkgs})
	resolver := NewPkgResolver(context.Background(), testNamedRepositoryFromIndexes([]*RepositoryWithIndex{repoWithIndex}))

	// pkg-a is listed first so postgresql-15 lands in dependenciesMap before
	// pkg-b is resolved, giving existingOrigins the postgresql/15.3-r1 entry.
	pkgs, _, err := resolver.GetPackagesWithDependencies(
		context.Background(), []string{"pkg-a", "pkg-b"}, nil)
	require.NoError(t, err)

	names := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		names = append(names, p.Filename())
	}
	require.Contains(t, names, "postgresql-15-15.3-r1.apk")
	require.Contains(t, names, "libpq-15-15.3-r1.apk")
	require.Contains(t, names, "pkg-a-1.0.apk")
	require.Contains(t, names, "pkg-b-1.0.apk")
	require.NotContains(t, names, "libpq-15-15.4-r0.apk")
}
