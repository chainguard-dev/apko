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
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	apkfs "chainguard.dev/apko/pkg/apk/impl/fs"
)

var testDemoKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwXEJ8uVwJPODshTkf2BH
pH5fVVDppOa974+IQJsZDmGd3Ny0dcd+WwYUhNFUW3bAfc3/egaMWCaprfaHn+oS
4ddbOFgbX8JCHdru/QMAAU0aEWSMybfJGA569c38fNUF/puX6XK/y0lD2SS3YQ/a
oJ5jb5eNrQGR1HHMAd0G9WC4JeZ6WkVTkrcOw55F00aUPGEjejreXBerhTyFdabo
dSfc1TILWIYD742Lkm82UBOPsOSdSfOdsMOOkSXxhdCJuCQQ70DHkw7Epy9r+X33
ybI4r1cARcV75OviyhD8CFhAlapLKaYnRFqFxlA515e6h8i8ih/v3MSEW17cCK0b
QwIDAQAB
-----END PUBLIC KEY-----
`

func TestInitDB(t *testing.T) {
	src := apkfs.NewMemFS()
	apk, err := NewAPKImplementation(WithFS(src), WithIgnoreMknodErrors(ignoreMknodErrors))
	require.NoError(t, err)
	baseDirs := []string{"/tmp", "/proc", "/dev", "/var", "/lib", "/etc"}
	for _, d := range baseDirs {
		err := src.MkdirAll(d, 0o755)
		require.NoError(t, err, "error creating %s", d)
	}
	err = apk.InitDB()
	require.NoError(t, err)
	// check all of the contents
	for _, d := range initDirectories {
		fi, err := fs.Stat(src, d.path)
		require.NoError(t, err, "error statting %s", d.path)
		require.True(t, fi.IsDir(), "expected %s to be a directory, got %v", d.path, fi.Mode())
		require.Equal(t, d.perms, fi.Mode().Perm(), "expected %s to have permissions %v, got %v", d.path, d.perms, fi.Mode().Perm())
	}
	for _, f := range initFiles {
		fi, err := fs.Stat(src, f.path)
		require.NoError(t, err, "error statting %s", f.path)
		require.True(t, fi.Mode().IsRegular(), "expected %s to be a regular file, got %v", f.path, fi.Mode())
		require.Equal(t, f.perms, fi.Mode().Perm(), "mismatched permissions for %s", f.path)
		require.GreaterOrEqual(t, fi.Size(), int64(len(f.contents)), "mismatched size for %s", f.path) // actual file can be bigger than original size
	}
	if !ignoreMknodErrors {
		for _, f := range initDeviceFiles {
			fi, err := fs.Stat(src, f.path)
			require.NoError(t, err, "error statting %s", f.path)
			require.Equal(t, fi.Mode().Type()&os.ModeCharDevice, os.ModeCharDevice, "expected %s to be a character file, got %v", f.path, fi.Mode())
			require.Equal(t, f.perms, fi.Mode().Perm(), "expected %s to have permissions %v, got %v", f.path, f.perms, fi.Mode().Perm())
		}
	}
}

func TestSetWorld(t *testing.T) {
	src := apkfs.NewMemFS()
	apk, err := NewAPKImplementation(WithFS(src), WithIgnoreMknodErrors(ignoreMknodErrors))
	require.NoError(t, err)
	// for initialization
	err = src.MkdirAll("etc/apk", 0o755)
	require.NoError(t, err)

	// set these packages in a random order; it should write them to world in the correct order
	packages := []string{"foo", "bar", "abc", "zulu"}
	err = apk.SetWorld(packages)
	require.NoError(t, err)

	// check all of the contents
	actual, err := src.ReadFile("etc/apk/world")
	require.NoError(t, err)

	sort.Strings(packages)
	expected := strings.Join(packages, "\n")
	require.Equal(t, expected, string(actual), "unexpected content for etc/apk/world:\nexpected %s\nactual %s", expected, actual)
}

func TestSetRepositories(t *testing.T) {
	src := apkfs.NewMemFS()
	apk, err := NewAPKImplementation(WithFS(src), WithIgnoreMknodErrors(ignoreMknodErrors))
	require.NoError(t, err)
	// for initialization

	err = src.MkdirAll("etc/apk", 0o755)
	require.NoError(t, err)

	repos := []string{"https://dl-cdn.alpinelinux.org/alpine/v3.16/main", "https://dl-cdn.alpinelinux.org/alpine/v3.16/community"}
	err = apk.SetRepositories(repos)
	require.NoError(t, err)

	// check all of the contents
	actual, err := src.ReadFile("etc/apk/repositories")
	require.NoError(t, err)

	expected := strings.Join(repos, "\n")
	require.Equal(t, expected, string(actual), "unexpected content for etc/apk/repositories:\nexpected %s\nactual %s", expected, actual)
}

func TestInitKeyring(t *testing.T) {
	src := apkfs.NewMemFS()
	a, err := NewAPKImplementation(WithFS(src), WithIgnoreMknodErrors(ignoreMknodErrors))
	require.NoError(t, err)

	dir, err := os.MkdirTemp("", "apko")
	require.NoError(t, err)

	keyPath := filepath.Join(dir, "alpine-devel@lists.alpinelinux.org-5e69ca50.rsa.pub")
	err = os.WriteFile(keyPath, []byte(testDemoKey), 0o644)
	require.NoError(t, err)

	// Add a local file and a remote key
	keyfiles := []string{
		keyPath, "https://alpinelinux.org/keys/alpine-devel%40lists.alpinelinux.org-4a6a0840.rsa.pub",
	}
	// ensure we send things from local
	a.SetClient(&http.Client{
		Transport: &testLocalTransport{root: "testdata", basenameOnly: true},
	})

	require.NoError(t, a.InitKeyring(keyfiles, nil))
	// InitKeyring should have copied the local key and remote key to the right place
	fi, err := src.ReadDir(DefaultKeyRingPath)
	// should be no error reading them
	require.NoError(t, err)
	// should be 2 keys
	require.Len(t, fi, 2)

	// Add an invalid file
	keyfiles = []string{
		"/liksdjlksdjlksjlksjdl",
	}
	require.Error(t, a.InitKeyring(keyfiles, nil))

	// Add an invalid url
	keyfiles = []string{
		"http://sldkjflskdjflklksdlksdlkjslk.net",
	}
	require.Error(t, a.InitKeyring(keyfiles, nil))
}

func TestLoadSystemKeyring(t *testing.T) {
	t.Run("non-existent dir", func(t *testing.T) {
		src := apkfs.NewMemFS()
		a, err := NewAPKImplementation(WithFS(src), WithIgnoreMknodErrors(ignoreMknodErrors))
		require.NoError(t, err)

		// Read the empty dir, passing a non-existent location should err
		_, err = a.loadSystemKeyring("/non/existent/dir")
		require.Error(t, err)
	})
	t.Run("empty dir", func(t *testing.T) {
		src := apkfs.NewMemFS()
		a, err := NewAPKImplementation(WithFS(src), WithIgnoreMknodErrors(ignoreMknodErrors))
		require.NoError(t, err)

		// Read the empty dir, passing only one empty location should err
		emptyDir := "/var/test/keyring"
		err = src.MkdirAll(emptyDir, 0o755)
		require.NoError(t, err)
		_, err = a.loadSystemKeyring(emptyDir)
		require.Error(t, err)
	})
	tests := []struct {
		name  string
		paths []string
	}{
		{"non-standard dir", []string{"/var/test/keyring"}},
		{"standard dir", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			arch := ArchToAPK(runtime.GOARCH)
			src := apkfs.NewMemFS()
			a, err := NewAPKImplementation(WithFS(src), WithIgnoreMknodErrors(ignoreMknodErrors))
			require.NoError(t, err)

			// Write some dummy keyfiles in a random location
			targetDir := DefaultSystemKeyRingPath
			if len(tt.paths) > 0 {
				targetDir = tt.paths[0]
			}
			// make the base directory and the arch-specific directory
			err = src.MkdirAll(targetDir, 0o755)
			require.NoError(t, err)
			err = src.MkdirAll(filepath.Join(targetDir, arch), 0o755)
			require.NoError(t, err)
			for _, h := range []string{"4a6a0840", "5243ef4b", "5261cecb", "6165ee59", "61666e3f"} {
				require.NoError(t, src.WriteFile(
					filepath.Join(targetDir, fmt.Sprintf("alpine-devel@lists.alpinelinux.org-%s.rsa.pub", h)),
					[]byte("testABC"), os.FileMode(0o644),
				))
			}

			for _, h := range []string{"4a6a0840", "5243ef4b", "5261cecb", "6165ee59", "61666e3f"} {
				err := src.WriteFile(
					filepath.Join(targetDir, arch, fmt.Sprintf("alpine-devel@lists.alpinelinux.org-%s.rsa.pub", h)),
					[]byte("testABC"), os.FileMode(0o644),
				)
				require.NoError(t, err)
			}

			// Add a readme file to ensure we dont read it
			require.NoError(t, src.WriteFile(
				filepath.Join(targetDir, "README.txt"), []byte("testABC"), os.FileMode(0o644),
			))

			// Successful read
			keyFiles, err := a.loadSystemKeyring(tt.paths...)
			require.NoError(t, err)
			require.Len(t, keyFiles, 5)
			// should not take into account extraneous files
			require.NotContains(t, keyFiles, filepath.Join(targetDir, "README.txt"))
		})
	}
}

func TestFixateWorld(t *testing.T) {

}
