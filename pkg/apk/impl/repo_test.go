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

package impl

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
	"gitlab.alpinelinux.org/alpine/go/repository"

	apkfs "chainguard.dev/apko/pkg/apk/impl/fs"
)

func TestGetRepositoryIndexes(t *testing.T) {
	src := apkfs.NewMemFS()
	err := src.MkdirAll("etc/apk", 0755)
	require.NoError(t, err, "unable to mkdir /etc/apk")
	err = src.WriteFile(reposFilePath, []byte("https://dl-cdn.alpinelinux.org/alpine/v3.16/main"), 0644)
	require.NoErrorf(t, err, "unable to write repositories")
	err = src.WriteFile(archFilePath, []byte("aarch64\n"), 0644)
	require.NoErrorf(t, err, "unable to write arch")
	err = src.MkdirAll(keysDirPath, 0755)
	require.NoError(t, err, "unable to mkdir /etc/apk/keys")
	err = src.WriteFile("etc/apk/keys/alpine-devel@lists.alpinelinux.org-616ae350.rsa.pub", []byte(`
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
-----END PUBLIC KEY-----`), 0644)
	require.NoError(t, err, "unable to write key")
	err = src.WriteFile("etc/apk/keys/alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub", []byte(`
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
-----END PUBLIC KEY-----`), 0644)
	require.NoError(t, err, "unable to write key")

	a, err := NewAPKImplementation(WithFS(src), WithIgnoreMknodErrors(ignoreMknodErrors))
	require.NoError(t, err, "unable to create APKImplementation")

	// set a client so we use local testdata instead of heading out to the Internet each time
	a.SetClient(&http.Client{
		Transport: &testLocalTransport{root: "testdata", basenameOnly: true},
	})
	indexes, err := a.getRepositoryIndexes(false)
	require.NoErrorf(t, err, "unable to get indexes")
	require.Greater(t, len(indexes), 0, "no indexes found")
}

//nolint:unparam // nothing uses the first arg for now, but we want to keep this around
func testGetPackagesAndIndex() ([]*repository.RepositoryPackage, []*repository.RepositoryWithIndex) {
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
	*/
	// a depth-first search gives the following for package1
	// dep5, dep4, dep1, libq, foo, dep6, dep3, busybox, dep2, libq, foo, dep6, dep3
	// when deduplicated by first-before-last (because we did depth-first),
	// we get
	// dep4, dep5, dep1, dep6, foo, libq, dep3, busybox, dep2
	var (
		packages = []*repository.Package{
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
		}
		repoPackages = make([]*repository.RepositoryPackage, 0, len(packages))
	)

	for _, pkg := range packages {
		repoPackages = append(repoPackages, &repository.RepositoryPackage{Package: pkg})
	}
	repo := repository.Repository{}
	repoWithIndex := repo.WithIndex(&repository.ApkIndex{
		Packages: packages,
	})
	return repoPackages, []*repository.RepositoryWithIndex{repoWithIndex}
}

func TestGetPackagesWithDependences(t *testing.T) {
	_, index := testGetPackagesAndIndex()

	names := []string{"package1", "package2"}
	expectedPackage1 := []string{"dep4", "dep5", "dep1", "dep6", "foo", "libq", "dep3", "busybox", "dep2", "package1"}
	expectedPackage2 := []string{"dep7", "package2"}
	expected := make([]string, 0, len(expectedPackage1)+len(expectedPackage2))
	expected = append(expected, expectedPackage1...)
	expected = append(expected, expectedPackage2...)
	// this should do a few things:
	// - find all of the dependencies of all of the packages
	// - eliminate duplicates
	// - reverse the order, so that it is in order of installation
	resolver := NewPkgResolver(testNamedRepositoryFromIndexes(index))
	pkgs, _, err := resolver.GetPackagesWithDependencies(names)
	require.NoErrorf(t, err, "unable to get packages")
	var actual = make([]string, 0, len(pkgs))
	for _, pkg := range pkgs {
		actual = append(actual, pkg.Name)
	}
	require.True(t, reflect.DeepEqual(expected, actual), "packages mismatch:\nactual %v\nexpect %v", actual, expected)
}
func TestGetPackageDependencies(t *testing.T) {
	t.Run("normal dependencies", func(t *testing.T) {
		// getPackageDependencies does not get the same dependencies twice.
		expected := []string{"dep4", "dep5", "dep1", "dep6", "foo", "libq", "dep3", "busybox", "dep2"}
		_, index := testGetPackagesAndIndex()

		resolver := NewPkgResolver(testNamedRepositoryFromIndexes(index))
		_, pkgs, _, err := resolver.GetPackageWithDependencies("package1", nil)
		require.NoErrorf(t, err, "unable to get dependencies")

		var actual = make([]string, 0, len(pkgs))
		for _, p := range pkgs {
			actual = append(actual, p.Name)
		}
		require.True(t, reflect.DeepEqual(expected, actual), "dependencies mismatch:\nactual %v\nexpect %v", actual, expected)
	})
	t.Run("circular dependencies", func(t *testing.T) {
		// getPackageDependencies does not get the same dependencies twice.
		expected := []string{"dep8"}
		_, index := testGetPackagesAndIndex()

		resolver := NewPkgResolver(testNamedRepositoryFromIndexes(index))
		_, pkgs, _, err := resolver.GetPackageWithDependencies("package3", nil)
		require.NoErrorf(t, err, "unable to get dependencies")

		var actual = make([]string, 0, len(pkgs))
		for _, p := range pkgs {
			actual = append(actual, p.Name)
		}
		require.True(t, reflect.DeepEqual(expected, actual), "dependencies mismatch:\nactual %v\nexpect %v", actual, expected)
	})
}

// Make sure that all versions exist
func TestVersionHierarchy(t *testing.T) {
	repo := repository.Repository{}
	index := repo.WithIndex(&repository.ApkIndex{
		Packages: []*repository.Package{
			{Name: "multi-versioner", Version: "1.2.3-r0"},
			{Name: "multi-versioner", Version: "1.3.6-r0"},
			{Name: "multi-versioner", Version: "1.2.8-r0"},
			{Name: "multi-versioner", Version: "1.7.1-r0"},
			{Name: "multi-versioner", Version: "1.7.1-r1"},
			{Name: "multi-versioner", Version: "2.0.6-r0"},
		},
	})
	resolver := NewPkgResolver(testNamedRepositoryFromIndexes([]*repository.RepositoryWithIndex{index}))
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
		pkg   *repository.Package
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
			{&repository.Package{Name: "package1", Version: "1.0.0"}, "http://a.b.com", 2},
			{&repository.Package{Name: "package1", Version: "2.0.1"}, "http://a.b.com", 0},
			{&repository.Package{Name: "package1", Version: "1.2.0"}, "http://a.b.com", 1},
		}, nil, nil},
		{"just names", []repoPkgBase{
			{&repository.Package{Name: "package1", Version: "1.0.0"}, "http://a.b.com", 1},
			{&repository.Package{Name: "package2", Version: "1.0.0"}, "http://a.b.com", 2},
			{&repository.Package{Name: "earlier", Version: "1.0.0"}, "http://a.b.com", 0},
		}, nil, nil},
		{"just origins", []repoPkgBase{
			{&repository.Package{Name: "package1", Version: "1.0.0", Origin: "c"}, "http://a.b.com", 2},
			{&repository.Package{Name: "package1", Version: "2.0.1", Origin: "b"}, "http://a.b.com", 1},
			{&repository.Package{Name: "package1", Version: "1.2.0", Origin: "a"}, "http://a.b.com", 0},
		}, &repoPkgBase{&repository.Package{Origin: "a"}, "", 0}, nil},
		{"just repositories", []repoPkgBase{
			{&repository.Package{Name: "package1", Version: "1.0.0", Origin: "c"}, "http://other.com", 2},
			{&repository.Package{Name: "package1", Version: "2.0.1", Origin: "b"}, "http://example.com", 1},
			{&repository.Package{Name: "package1", Version: "1.2.0", Origin: "a"}, "http://a.b.com", 0},
		}, &repoPkgBase{&repository.Package{Origin: "a"}, "http://a.b.com", 0}, nil},
		{"just existing", []repoPkgBase{
			{&repository.Package{Name: "package1", Version: "1.0.0", Origin: "c"}, "http://other.com", 0},
			{&repository.Package{Name: "package1", Version: "2.0.1", Origin: "b"}, "http://example.com", 1},
			{&repository.Package{Name: "package1", Version: "1.2.0", Origin: "a"}, "http://a.b.com", 2},
		}, nil, []repoPkgBase{
			{&repository.Package{Name: "package1", Version: "1.0.0", Origin: "c"}, "http://other.com", 0},
		}},
		{"origins and versions", []repoPkgBase{
			{&repository.Package{Name: "package1", Version: "1.0.0", Origin: "a"}, "http://a.b.com", 1},
			{&repository.Package{Name: "package1", Version: "2.0.1", Origin: "b"}, "http://a.b.com", 2},
			{&repository.Package{Name: "package1", Version: "1.2.0", Origin: "a"}, "http://a.b.com", 0},
		}, &repoPkgBase{&repository.Package{Origin: "a"}, "", 0}, nil},
		{"origins and repositories and versions", []repoPkgBase{
			{&repository.Package{Name: "package1", Version: "1.0.0", Origin: "a"}, "http://a.b.com", 1},
			{&repository.Package{Name: "package1", Version: "2.0.1", Origin: "b"}, "http://other.com", 4},
			{&repository.Package{Name: "package1", Version: "2.0.0", Origin: "b"}, "http://other.com", 5},
			{&repository.Package{Name: "package1", Version: "1.0.0", Origin: "c"}, "http://a.b.com", 2},
			{&repository.Package{Name: "package1", Version: "1.2.0", Origin: "a"}, "http://example.com", 3},
			{&repository.Package{Name: "package1", Version: "1.2.0", Origin: "a"}, "http://a.b.com", 0},
		}, &repoPkgBase{&repository.Package{Origin: "a"}, "http://a.b.com", 0}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				pkgs     []*repository.RepositoryPackage
				pkg      *repository.RepositoryPackage
				existing = map[string]*repository.RepositoryPackage{}
			)
			for _, pkg := range tt.pkgs {
				// we cheat and use the InstalledSize for the preferred order, so that it gets carried around.
				// this only works because the sorting algorithm does not look at or depend upon InstalledSize.
				// if we ever change that, we'll need to change this test.
				pkg.pkg.InstalledSize = uint64(pkg.order)
				pkgs = append(pkgs, repository.NewRepositoryPackage(pkg.pkg, &repository.RepositoryWithIndex{Repository: &repository.Repository{Uri: pkg.repo}}))
			}
			if tt.compare != nil {
				pkg = repository.NewRepositoryPackage(tt.compare.pkg, &repository.RepositoryWithIndex{Repository: &repository.Repository{Uri: tt.compare.repo}})
			}
			for _, pkg := range tt.existing {
				existing[pkg.pkg.Name] = repository.NewRepositoryPackage(pkg.pkg, &repository.RepositoryWithIndex{Repository: &repository.Repository{Uri: pkg.repo}})
			}
			namedPkgs := testNamedPackageFromPackages(pkgs)
			sortPackages(namedPkgs, pkg, existing, "")
			for i, pkg := range namedPkgs {
				require.Equal(t, int(pkg.InstalledSize), i, "position matches")
			}
		})
	}
}

func testNamedRepositoryFromIndexes(indexes []*repository.RepositoryWithIndex) (named []*namedRepositoryWithIndex) {
	for _, index := range indexes {
		named = append(named, &namedRepositoryWithIndex{repo: index})
	}
	return
}

func testNamedPackageFromPackages(pkgs []*repository.RepositoryPackage) (named []*repositoryPackage) {
	for _, pkg := range pkgs {
		named = append(named, &repositoryPackage{RepositoryPackage: pkg})
	}
	return
}

func testNamedPackageFromVersionAndPin(version, pin string) *repositoryPackage {
	return &repositoryPackage{RepositoryPackage: &repository.RepositoryPackage{Package: &repository.Package{Version: version}}, pinnedName: pin}
}
