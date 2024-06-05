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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1" //nolint:gosec // this is what apk tools is using
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"io/fs"
	"os"
	"testing"
	"text/template"

	"github.com/stretchr/testify/require"
)

type testDirEntry struct {
	path    string
	perms   os.FileMode
	dir     bool
	content []byte
	xattrs  map[string][]byte
}

func TestInstallAPKFiles(t *testing.T) {
	t.Run("basic", func(t *testing.T) {
		apk, src, err := testGetTestAPK()
		require.NoErrorf(t, err, "failed to get test APK")

		// create a tgz stream with our files
		entries := []testDirEntry{
			// do the dirs first so we are assured they go in before files
			{"etc", 0o755, true, nil, nil},
			{"etc/foo", 0o755, true, nil, nil},
			{"var", 0o755, true, nil, nil},
			{"var/lib", 0o755, true, nil, nil},
			{"var/lib/test", 0o755, true, nil, nil},

			{"etc/foo/bar", 0644, false, []byte("hello world"), nil},
			{"var/lib/test/foobar", 0644, false, []byte("hello var/lib"), nil},
			{"etc/other", 0644, false, []byte("first"), nil},
		}

		r := testCreateTarForPackage(entries)
		headers, err := apk.installAPKFiles(context.Background(), r, &Package{Origin: ""})
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
				require.Equal(t, int64(e.perms), h.Mode, "mismatched permissions for %s", name)
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

	t.Run("xattrs", func(t *testing.T) {
		apk, src, err := testGetTestAPK()
		require.NoErrorf(t, err, "failed to get test APK")

		// create a tgz stream with our files
		entries := []testDirEntry{
			// do the dirs first so we are assured they go in before files
			{"etc", 0o755, true, nil, map[string][]byte{"user.etc": []byte("hello world")}},
			{"etc/foo", 0o644, false, []byte("hello world"), map[string][]byte{"user.file": []byte("goodbye now")}},
		}

		r := testCreateTarForPackage(entries)
		headers, err := apk.installAPKFiles(context.Background(), r, &Package{})
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
			require.True(t, ok, "target %s not found in headers", name)
			for k, v := range e.xattrs {
				val, ok := h.PAXRecords[fmt.Sprintf("%s%s", xattrTarPAXRecordsPrefix, k)]
				require.True(t, ok, "xattr %s not found in headers for %s", k, name)
				require.Equal(t, val, string(v), "mismatched xattr %s for %s", k, name)
			}
		}

		// compare each one in the memfs filesystem to make sure it was installed correctly
		for _, e := range entries {
			name := e.path
			xattrs, err := src.ListXattrs(name)
			require.NoError(t, err, "error getting xattrs %s", name)
			require.Equal(t, len(xattrs), len(e.xattrs), "mismatched number of xattrs for %s", name)
			for k, v := range e.xattrs {
				require.Equal(t, v, xattrs[k], "mismatched xattr %s for %s", k, name)
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
			overwriteFilename := "etc/doublewrite" //nolint:goconst

			pkg := &Package{Name: "first", Origin: "first"}
			fp1 := fakePackage(t, pkg, []testDirEntry{
				{"etc", 0o755, true, nil, nil},
				{overwriteFilename, 0o755, false, originalContent, nil},
			})

			pkg2 := &Package{Name: "second", Origin: "second"}
			fp2 := fakePackage(t, pkg2, []testDirEntry{
				{"etc", 0o755, true, nil, nil},
				{overwriteFilename, 0o755, false, finalContent, nil},
			})

			err = apk.InstallPackages(context.Background(), nil, []InstallablePackage{fp1, fp2})
			require.Error(t, err, "some double-write error")

			actual, err := src.ReadFile(overwriteFilename)
			require.NoError(t, err, "error reading %s", overwriteFilename)
			require.Equal(t, originalContent, actual)

			checkDuplicateIDBEntries(t, apk)
		})
		t.Run("different origin and content, but with replaces", func(t *testing.T) {
			apk, src, err := testGetTestAPK()
			require.NoErrorf(t, err, "failed to get test APK")
			// install a file in a known location
			originalContent := []byte("hello world")
			finalContent := []byte("extra long I am here")
			overwriteFilename := "etc/doublewrite"

			pkg := &Package{Name: "first", Origin: "first"}
			fp1 := fakePackage(t, pkg, []testDirEntry{
				{"etc", 0755, true, nil, nil},
				{overwriteFilename, 0755, false, originalContent, nil},
			})

			pkg2 := &Package{Name: "second", Origin: "second", Replaces: []string{"first"}}
			fp2 := fakePackage(t, pkg2, []testDirEntry{
				{"etc", 0755, true, nil, nil},
				{overwriteFilename, 0755, false, finalContent, nil},
			})

			err = apk.InstallPackages(context.Background(), nil, []InstallablePackage{fp1, fp2})
			require.NoError(t, err)

			actual, err := src.ReadFile(overwriteFilename)
			require.NoError(t, err, "error reading %s", overwriteFilename)
			require.Equal(t, finalContent, actual)

			checkDuplicateIDBEntries(t, apk)
		})
		t.Run("same origin", func(t *testing.T) {
			apk, src, err := testGetTestAPK()
			require.NoErrorf(t, err, "failed to get test APK")
			// install a file in a known location
			originalContent := []byte("hello world")
			finalContent := []byte("extra long I am here")
			overwriteFilename := "etc/doublewrite"

			pkg := &Package{Name: "first", Origin: "first"}
			fp1 := fakePackage(t, pkg, []testDirEntry{
				{"etc", 0o755, true, nil, nil},
				{overwriteFilename, 0o755, false, originalContent, nil},
			})

			pkg2 := &Package{Name: "first-compat", Origin: "first"}
			fp2 := fakePackage(t, pkg2, []testDirEntry{
				{"etc", 0o755, true, nil, nil},
				{overwriteFilename, 0o755, false, finalContent, nil},
			})

			err = apk.InstallPackages(context.Background(), nil, []InstallablePackage{fp1, fp2})
			require.NoError(t, err)

			actual, err := src.ReadFile(overwriteFilename)
			require.NoError(t, err, "error reading %s", overwriteFilename)
			require.Equal(t, finalContent, actual)

			checkDuplicateIDBEntries(t, apk)
		})
		t.Run("different origin with same content", func(t *testing.T) {
			apk, src, err := testGetTestAPK()
			require.NoErrorf(t, err, "failed to get test APK")
			// install a file in a known location
			originalContent := []byte("hello world")
			overwriteFilename := "etc/doublewrite"

			pkg := &Package{Name: "first", Origin: "first"}
			fp1 := fakePackage(t, pkg, []testDirEntry{
				{"etc", 0o755, true, nil, nil},
				{overwriteFilename, 0o755, false, originalContent, nil},
			})

			pkg2 := &Package{Name: "second", Origin: "second"}
			fp2 := fakePackage(t, pkg2, []testDirEntry{
				{"etc", 0o755, true, nil, nil},
				{overwriteFilename, 0o755, false, originalContent, nil},
			})

			err = apk.InstallPackages(context.Background(), nil, []InstallablePackage{fp1, fp2})
			require.NoError(t, err)

			actual, err := src.ReadFile(overwriteFilename)
			require.NoError(t, err, "error reading %s", overwriteFilename)
			require.Equal(t, originalContent, actual)

			checkDuplicateIDBEntries(t, apk)
		})
		t.Run("different origin and content, but is replaced", func(t *testing.T) {
			apk, src, err := testGetTestAPK()
			require.NoErrorf(t, err, "failed to get test APK")
			// install a file in a known location
			originalContent := []byte("hello world")
			finalContent := []byte("extra long I am here")
			overwriteFilename := "etc/doublewrite"

			pkg := &Package{Name: "first", Origin: "first", Replaces: []string{"second"}}
			fp1 := fakePackage(t, pkg, []testDirEntry{
				{"etc", 0755, true, nil, nil},
				{overwriteFilename, 0755, false, originalContent, nil},
			})

			pkg2 := &Package{Name: "second", Origin: "second"}
			fp2 := fakePackage(t, pkg2, []testDirEntry{
				{"etc", 0755, true, nil, nil},
				{overwriteFilename, 0755, false, finalContent, nil},
			})

			err = apk.InstallPackages(context.Background(), nil, []InstallablePackage{fp1, fp2})
			require.NoError(t, err)

			actual, err := src.ReadFile(overwriteFilename)
			require.NoError(t, err, "error reading %s", overwriteFilename)
			require.Equal(t, originalContent, actual)

			checkDuplicateIDBEntries(t, apk)
		})
	})
}

func checkDuplicateIDBEntries(t *testing.T, apk *APK) {
	t.Helper()

	// Ensure there are not any files that are owned by two packages.
	installed, err := apk.GetInstalled()
	require.NoError(t, err)

	errored := false

	files := map[string]string{}
	for _, pkg := range installed {
		for _, f := range pkg.Files {
			if f.Typeflag == tar.TypeDir {
				continue
			}

			owner, ok := files[f.Name]
			if ok {
				errored = true
				t.Errorf("duplicate file entry in idb: %q in packages %q and %q", f.Name, owner, pkg.Name)
			} else {
				files[f.Name] = pkg.Name
			}
		}
	}

	if errored {
		b, err := apk.fs.ReadFile(installedFilePath)
		require.NoError(t, err)
		t.Logf("idb contents:\n%s", b)
	}
}

type testPackage struct {
	file     string
	pkg      *Package
	checksum string
}

func (t *testPackage) URL() string {
	return t.file
}

func (t *testPackage) PackageName() string {
	return t.pkg.Name
}

func (t *testPackage) ChecksumString() string {
	return t.checksum
}

func fakePackage(t *testing.T, pkg *Package, entries []testDirEntry) InstallablePackage {
	t.Helper()

	dir := t.TempDir()
	f, err := os.CreateTemp(dir, pkg.Name)
	if err != nil {
		t.Fatal(err)
	}

	h := sha1.New() //nolint:gosec
	dh := sha256.New()

	mw := io.MultiWriter(f, h)

	zw := gzip.NewWriter(mw)
	tw := tar.NewWriter(zw)

	tmpl := template.New("control")
	var b bytes.Buffer
	if err := template.Must(tmpl.Parse(controlTemplate)).Execute(&b, pkg); err != nil {
		t.Fatal(err)
	}

	if err := tw.WriteHeader(&tar.Header{
		Name:     ".PKGINFO",
		Typeflag: tar.TypeReg,
		Size:     int64(b.Len()),
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := tw.Write(b.Bytes()); err != nil {
		t.Fatal(err)
	}

	if err := tw.Flush(); err != nil {
		t.Fatal(err)
	}

	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	mw = io.MultiWriter(f, dh)
	zw.Reset(mw)

	if err := writeFiles(tw, entries); err != nil {
		t.Fatal(err)
	}

	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	pkg.DataHash = base64.StdEncoding.EncodeToString(dh.Sum(nil))

	return &testPackage{
		pkg:      pkg,
		file:     f.Name(),
		checksum: base64.StdEncoding.EncodeToString(h.Sum(nil)),
	}
}

func writeFiles(tw *tar.Writer, entries []testDirEntry) error {
	for _, e := range entries {
		var header *tar.Header
		if e.dir {
			header = &tar.Header{
				Name:     e.path,
				Typeflag: tar.TypeDir,
				Mode:     int64(e.perms),
			}
		} else {
			header = &tar.Header{
				Name:     e.path,
				Typeflag: tar.TypeReg,
				Mode:     int64(e.perms),
				Size:     int64(len(e.content)),
			}
		}

		if e.xattrs != nil {
			header.Format = tar.FormatPAX
			if header.PAXRecords == nil {
				header.PAXRecords = make(map[string]string)
			}
			for k, v := range e.xattrs {
				header.PAXRecords[fmt.Sprintf("%s%s", xattrTarPAXRecordsPrefix, k)] = string(v)
			}
		}

		err := tw.WriteHeader(header)
		if err != nil {
			return err
		}
		if e.content != nil {
			_, err = tw.Write(e.content)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func testCreateTarForPackage(entries []testDirEntry) io.Reader {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	if err := writeFiles(tw, entries); err != nil {
		panic(err)
	}

	tw.Close()
	return bytes.NewReader(buf.Bytes())
}

var controlTemplate = `# generated by apko unit test
pkgname = {{.Name}}
pkgver = {{.Version}}
arch = {{.Arch}}
size = {{.InstalledSize}}
origin = {{.Origin}}
pkgdesc = {{.Description}}
url = {{.URL}}
commit = {{.RepoCommit}}
builddate = {{ .BuildDate }}
{{- range $dep := .Dependencies }}
depend = {{ $dep }}
{{- end }}
{{- range $dep := .Provides }}
provides = {{ $dep }}
{{- end }}
{{- range $dep := .Replaces }}
replaces = {{ $dep }}
{{- end }}
{{- if .ProviderPriority }}
provider_priority = {{ .Dependencies.ProviderPriority }}
{{- end }}
datahash = {{.DataHash}}
`
