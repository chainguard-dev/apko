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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"io/fs"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"gitlab.alpinelinux.org/alpine/go/repository"
)

type testDirEntry struct {
	path    string
	perms   os.FileMode
	dir     bool
	content []byte
}

func TestInstallAPKFiles(t *testing.T) {
	t.Run("basic", func(t *testing.T) {
		apk, src, err := testGetTestAPK()
		require.NoErrorf(t, err, "failed to get test APK")

		// create a tgz stream with our files
		entries := []testDirEntry{
			// do the dirs first so we are assured they go in before files
			{"etc", 0755, true, nil},
			{"etc/foo", 0755, true, nil},
			{"var", 0755, true, nil},
			{"var/lib", 0755, true, nil},
			{"var/lib/test", 0755, true, nil},

			{"etc/foo/bar", 0644, false, []byte("hello world")},
			{"var/lib/test/foobar", 0644, false, []byte("hello var/lib")},
			{"etc/other", 0644, false, []byte("first")},
		}

		r := testCreateTGZForPackage(entries)
		headers, err := apk.installAPKFiles(r, "", "")
		require.NoError(t, err)

		require.Equal(t, len(headers), len(entries))

		// compare each one to make sure it is in the returned list
		headerMap := map[string]tar.Header{}
		for _, h := range headers {
			headerMap[h.Name] = h
		}
		for _, e := range entries {
			name := e.path
			h, ok := headerMap[name]
			if e.dir {
				require.True(t, ok, "directory %s not found in headers", name)
				require.Equal(t, tar.TypeDir, rune(h.Typeflag), "mismatched file type for %s", name)
				require.Equal(t, int64(os.ModeDir|e.perms), h.Mode, "mismatched permissions for %s", name)
			} else {
				require.True(t, ok, "file %s not found in headers", name)
				require.Equal(t, tar.TypeReg, rune(h.Typeflag), "mismatched file type for %s", name)
				require.Equal(t, h.Mode, int64(e.perms), "mismatched permissions for %s", name)
				require.Equal(t, int64(len(e.content)), h.Size, "mismatched size for %s", name)
			}
			delete(headerMap, name)
		}

		// compare each one in the memfs filesystem to make sure it was installed correctly
		for _, e := range entries {
			name := e.path
			fi, err := fs.Stat(src, name)
			require.NoError(t, err, "error statting %s", name)
			if e.dir {
				require.True(t, fi.IsDir(), "expected %s to be a directory, got %v", name, fi.Mode())
				require.Equal(t, fi.Mode(), os.ModeDir|e.perms, "expected %s to have permissions %v, got %v", name, e.perms, fi.Mode())
			} else {
				require.True(t, fi.Mode().IsRegular(), "expected %s to be a regular file, got %v", name, fi.Mode())
				require.Equal(t, fi.Mode(), e.perms, "expected %s to have permissions %v, got %v", name, e.perms, fi.Mode())
				require.Equal(t, fi.Size(), int64(len(e.content)), "expected %s to have size %d, got %d", name, len(e.content), fi.Size())
				actual, err := src.ReadFile(name)
				require.NoError(t, err, "error reading %s", name)
				require.True(t, bytes.Equal(actual, e.content), "unexpected content for %s: expected %q, got %q", name, e.content, actual)
			}
		}
	})
	t.Run("overlapping files", func(t *testing.T) {
		t.Run("different origin and content", func(t *testing.T) {
			apk, src, err := testGetTestAPK()
			require.NoErrorf(t, err, "failed to get test APK")
			// install a file in a known location
			originalContent := []byte("hello world")
			finalContent := []byte("extra long I am here")
			overwriteFilename := "etc/doublewrite"

			pkg := &repository.Package{Name: "first", Origin: "first"}

			entries := []testDirEntry{
				{"etc", 0755, true, nil},
				{overwriteFilename, 0755, false, originalContent},
			}

			r := testCreateTGZForPackage(entries)
			headers, err := apk.installAPKFiles(r, pkg.Origin, "")
			require.NoError(t, err)
			err = apk.addInstalledPackage(pkg, headers)
			require.NoError(t, err)

			actual, err := src.ReadFile(overwriteFilename)
			require.NoError(t, err, "error reading %s", overwriteFilename)
			require.Equal(t, originalContent, actual)

			entries = []testDirEntry{
				{overwriteFilename, 0755, false, finalContent},
			}

			r = testCreateTGZForPackage(entries)
			_, err = apk.installAPKFiles(r, "second", "")
			require.Error(t, err, "some double-write error")

			actual, err = src.ReadFile(overwriteFilename)
			require.NoError(t, err, "error reading %s", overwriteFilename)
			require.Equal(t, originalContent, actual)
		})
		t.Run("different origin and content, but with replaces", func(t *testing.T) {
			apk, src, err := testGetTestAPK()
			require.NoErrorf(t, err, "failed to get test APK")
			// install a file in a known location
			originalContent := []byte("hello world")
			finalContent := []byte("extra long I am here")
			overwriteFilename := "etc/doublewrite"

			pkg := &repository.Package{Name: "first", Origin: "first"}

			entries := []testDirEntry{
				{"etc", 0755, true, nil},
				{overwriteFilename, 0755, false, originalContent},
			}

			r := testCreateTGZForPackage(entries)
			headers, err := apk.installAPKFiles(r, pkg.Origin, "")
			require.NoError(t, err)
			err = apk.addInstalledPackage(pkg, headers)
			require.NoError(t, err)

			actual, err := src.ReadFile(overwriteFilename)
			require.NoError(t, err, "error reading %s", overwriteFilename)
			require.Equal(t, originalContent, actual)

			entries = []testDirEntry{
				{overwriteFilename, 0755, false, finalContent},
			}

			r = testCreateTGZForPackage(entries)
			_, err = apk.installAPKFiles(r, "second", "first")
			require.NoError(t, err)

			actual, err = src.ReadFile(overwriteFilename)
			require.NoError(t, err, "error reading %s", overwriteFilename)
			require.Equal(t, finalContent, actual)
		})
		t.Run("same origin", func(t *testing.T) {
			apk, src, err := testGetTestAPK()
			require.NoErrorf(t, err, "failed to get test APK")
			// install a file in a known location
			originalContent := []byte("hello world")
			finalContent := []byte("extra long I am here")
			overwriteFilename := "etc/doublewrite"

			entries := []testDirEntry{
				{"etc", 0755, true, nil},
				{overwriteFilename, 0755, false, originalContent},
			}
			pkg := &repository.Package{Name: "first", Origin: "first"}

			r := testCreateTGZForPackage(entries)
			headers, err := apk.installAPKFiles(r, pkg.Origin, "")
			require.NoError(t, err)
			err = apk.addInstalledPackage(pkg, headers)
			require.NoError(t, err)

			actual, err := src.ReadFile(overwriteFilename)
			require.NoError(t, err, "error reading %s", overwriteFilename)
			require.Equal(t, originalContent, actual)

			entries = []testDirEntry{
				{overwriteFilename, 0755, false, finalContent},
			}

			r = testCreateTGZForPackage(entries)
			_, err = apk.installAPKFiles(r, pkg.Origin, "")
			require.NoError(t, err)

			actual, err = src.ReadFile(overwriteFilename)
			require.NoError(t, err, "error reading %s", overwriteFilename)
			require.Equal(t, finalContent, actual)
		})
		t.Run("different origin with same content", func(t *testing.T) {
			apk, src, err := testGetTestAPK()
			require.NoErrorf(t, err, "failed to get test APK")
			// install a file in a known location
			originalContent := []byte("hello world")
			overwriteFilename := "etc/doublewrite"

			pkg := &repository.Package{Name: "first", Origin: "first"}

			entries := []testDirEntry{
				{"etc", 0755, true, nil},
				{overwriteFilename, 0755, false, originalContent},
			}

			r := testCreateTGZForPackage(entries)
			headers, err := apk.installAPKFiles(r, pkg.Origin, "")
			require.NoError(t, err)
			err = apk.addInstalledPackage(pkg, headers)
			require.NoError(t, err)

			actual, err := src.ReadFile(overwriteFilename)
			require.NoError(t, err, "error reading %s", overwriteFilename)
			require.Equal(t, originalContent, actual)

			entries = []testDirEntry{
				{overwriteFilename, 0755, false, originalContent},
			}

			r = testCreateTGZForPackage(entries)
			_, err = apk.installAPKFiles(r, "second", "")
			require.NoError(t, err)

			actual, err = src.ReadFile(overwriteFilename)
			require.NoError(t, err, "error reading %s", overwriteFilename)
			require.Equal(t, originalContent, actual)
		})
	})
}

func testCreateTGZForPackage(entries []testDirEntry) io.Reader {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	for _, e := range entries {
		if e.dir {
			tw.WriteHeader(&tar.Header{
				Name:     e.path,
				Typeflag: tar.TypeDir,
				Mode:     int64(os.ModeDir | e.perms),
			})
		} else {
			tw.WriteHeader(&tar.Header{
				Name:     e.path,
				Typeflag: tar.TypeReg,
				Mode:     int64(e.perms),
				Size:     int64(len(e.content)),
			})
			tw.Write(e.content)
		}
	}
	tw.Close()
	gw.Close()
	return bytes.NewReader(buf.Bytes())
}
