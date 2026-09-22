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
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"testing/fstest"
	"text/template"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
)

type testDirEntry struct {
	path    string
	perms   os.FileMode
	dir     bool
	content []byte
	xattrs  map[string][]byte
}

func TestInstallAPKFiles(t *testing.T) {
	skipWithoutOwnerValidation(t)
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
			}, "")

			pkg2 := &Package{Name: "second", Origin: "second"}
			fp2 := fakePackage(t, pkg2, []testDirEntry{
				{"etc", 0o755, true, nil, nil},
				{overwriteFilename, 0o755, false, finalContent, nil},
			}, "")

			_, err = apk.InstallPackages(context.Background(), nil, []InstallablePackage{fp1, fp2})
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
			}, "")

			pkg2 := &Package{Name: "second", Origin: "second", Replaces: []string{"first"}}
			fp2 := fakePackage(t, pkg2, []testDirEntry{
				{"etc", 0755, true, nil, nil},
				{overwriteFilename, 0755, false, finalContent, nil},
			}, "")

			_, err = apk.InstallPackages(context.Background(), nil, []InstallablePackage{fp1, fp2})
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
			}, "")

			pkg2 := &Package{Name: "first-compat", Origin: "first"}
			fp2 := fakePackage(t, pkg2, []testDirEntry{
				{"etc", 0o755, true, nil, nil},
				{overwriteFilename, 0o755, false, finalContent, nil},
			}, "")

			_, err = apk.InstallPackages(context.Background(), nil, []InstallablePackage{fp1, fp2})
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
			}, "")

			pkg2 := &Package{Name: "second", Origin: "second"}
			fp2 := fakePackage(t, pkg2, []testDirEntry{
				{"etc", 0o755, true, nil, nil},
				{overwriteFilename, 0o755, false, originalContent, nil},
			}, "")

			_, err = apk.InstallPackages(context.Background(), nil, []InstallablePackage{fp1, fp2})
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
			}, "")

			pkg2 := &Package{Name: "second", Origin: "second"}
			fp2 := fakePackage(t, pkg2, []testDirEntry{
				{"etc", 0755, true, nil, nil},
				{overwriteFilename, 0755, false, finalContent, nil},
			}, "")

			_, err = apk.InstallPackages(context.Background(), nil, []InstallablePackage{fp1, fp2})
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

// fakePackage builds a well-formed synthetic APK. If dataHashOverride is
// non-empty it is written into .PKGINFO as the datahash instead of the real
// computed SHA-256 (use "" for a correctly-formed package).
func fakePackage(t *testing.T, pkg *Package, entries []testDirEntry, dataHashOverride string) *testPackage {
	t.Helper()

	// Pass 1: compute data section bytes and SHA-256.
	var dataBuf bytes.Buffer
	dh := sha256.New()
	dataZw := gzip.NewWriter(io.MultiWriter(&dataBuf, dh))
	dataTw := tar.NewWriter(dataZw)
	require.NoError(t, writeFiles(dataTw, entries))
	require.NoError(t, dataTw.Close())
	require.NoError(t, dataZw.Close())
	dataHash := hex.EncodeToString(dh.Sum(nil))
	if dataHashOverride != "" {
		dataHash = dataHashOverride
	}
	pkg.DataHash = dataHash

	// Pass 2: write control section (with datahash now set) then data bytes.
	f, err := os.CreateTemp(t.TempDir(), pkg.Name+"*.apk")
	require.NoError(t, err)

	h := sha1.New() //nolint:gosec
	ctlZw := gzip.NewWriter(io.MultiWriter(f, h))
	ctlTw := tar.NewWriter(ctlZw)

	var b bytes.Buffer
	require.NoError(t, template.Must(template.New("control").Parse(controlTemplate)).Execute(&b, pkg))
	require.NoError(t, ctlTw.WriteHeader(&tar.Header{
		Name:     ".PKGINFO",
		Typeflag: tar.TypeReg,
		Size:     int64(b.Len()),
	}))
	_, err = ctlTw.Write(b.Bytes())
	require.NoError(t, err)
	require.NoError(t, ctlTw.Close())
	require.NoError(t, ctlZw.Close())
	_, err = io.Copy(f, &dataBuf)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	return &testPackage{
		file:     f.Name(),
		pkg:      pkg,
		checksum: "Q1" + base64.StdEncoding.EncodeToString(h.Sum(nil)),
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

// TestInstallAPKFilesModesAndOwnership covers the metadata the streaming
// install path has to carry over from the tar headers: the mode bits outside
// of Perm(), and the ownership.
func TestInstallAPKFilesModesAndOwnership(t *testing.T) {
	skipWithoutOwnerValidation(t)
	type entry struct {
		name    string
		mode    int64 // POSIX mode bits, as they appear in a tar header
		dir     bool
		uid     int
		gid     int
		content []byte
	}
	entries := []entry{
		// dirs first, so they exist before the files under them
		{name: "opt", mode: 0o755, dir: true},
		{name: "opt/bin", mode: 0o755, dir: true},
		{name: "var", mode: 0o755, dir: true},
		{name: "var/spool", mode: 0o1777, dir: true},
		{name: "var/spool/postfix", mode: 0o2755, dir: true, gid: 101},
		// modelled on wolfi's postfix, which ships these setgid to gid 101
		{name: "opt/bin/postdrop", mode: 0o2755, gid: 101, content: []byte("postdrop")},
		{name: "opt/bin/plain", mode: 0o644, content: []byte("plain")},
		// a package that ships a header for a directory the base layout
		// already created must not overwrite what is there
		{name: "tmp", mode: 0o755, dir: true, uid: 7, gid: 7},
	}

	apk, src, err := testGetTestAPK()
	require.NoErrorf(t, err, "failed to get test APK")

	// stand in for InitDB, which creates /tmp as 1777 before any package installs
	require.NoError(t, src.MkdirAll("tmp", fs.ModeDir|fs.ModeSticky|0o777))
	require.NoError(t, src.Chmod("tmp", fs.ModeSticky|0o777))
	require.NoError(t, src.Chown("tmp", 5, 5))

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{
			Name:     e.name,
			Typeflag: tar.TypeReg,
			Mode:     e.mode,
			Uid:      e.uid,
			Gid:      e.gid,
			Size:     int64(len(e.content)),
		}
		if e.dir {
			hdr.Typeflag = tar.TypeDir
			hdr.Size = 0
		}
		require.NoError(t, tw.WriteHeader(hdr))
		if e.content != nil {
			_, err := tw.Write(e.content)
			require.NoError(t, err)
		}
	}
	require.NoError(t, tw.Close())

	_, err = apk.installAPKFiles(context.Background(), bytes.NewReader(buf.Bytes()), &Package{Origin: ""})
	require.NoError(t, err)

	for _, e := range entries {
		fi, err := src.Stat(e.name)
		require.NoError(t, err, "error statting %s", e.name)

		wantMode := (&tar.Header{Mode: e.mode}).FileInfo().Mode() &^ fs.ModeType
		wantUID, wantGID := e.uid, e.gid
		if e.name == "tmp" {
			// pre-existing: keeps the mode and owner it already had
			wantMode = fs.ModeSticky | 0o777
			wantUID, wantGID = 5, 5
		}
		if e.dir {
			wantMode |= fs.ModeDir
		}
		assert.Equal(t, wantMode, fi.Mode(), "mismatched mode for %s", e.name)

		hdr, ok := fi.Sys().(*tar.Header)
		require.True(t, ok, "no tar.Header from Sys() for %s", e.name)
		assert.Equal(t, wantUID, hdr.Uid, "mismatched uid for %s", e.name)
		assert.Equal(t, wantGID, hdr.Gid, "mismatched gid for %s", e.name)
	}
}

// skipWithoutOwnerValidation skips a test that installs package contents on a
// platform where checkArchiveOwner refuses every decoded header. Installing is
// deliberately impossible there -- archive/tar has already narrowed the owner
// and apko will not vouch for it -- so these tests have nothing to assert
// rather than something that broke. TestCheckArchiveOwnerRequires64BitInt
// covers the refusal itself.
func skipWithoutOwnerValidation(t *testing.T) {
	t.Helper()
	if math.MaxInt < math.MaxUint32 {
		t.Skip("installing requires owner validation, which requires a 64-bit int")
	}
}

// idsAsIntOrSkip narrows a row's uid/gid to an int for a tar.Header field,
// skipping the row where the value has no int form on this platform. Rows that
// do fit still run: a negative owner is representable everywhere, and it is
// checkOwner's other bound.
func idsAsIntOrSkip(t *testing.T, uid, gid int64) (int, int) {
	t.Helper()
	u, g := int(uid), int(gid)
	if int64(u) != uid || int64(g) != gid {
		t.Skipf("uid %d/gid %d are not representable in an int on this platform", uid, gid)
	}
	return u, g
}

// TestCheckArchiveOwnerRequires64BitInt pins the guard itself. archive/tar
// narrows uid/gid to an int on the way in ("Integer overflow possible" in
// mergePAX and readHeader), so where an int is 32 bits a declared uid of 2^32
// arrives as 0 and is indistinguishable from a package that really declared
// root. An unvalidatable owner has to be an error, not a pass.
//
// The guard is on checkArchiveOwner rather than checkOwner because only a
// decoded header is suspect; see the comment there.
func TestCheckArchiveOwnerRequires64BitInt(t *testing.T) {
	h := &tar.Header{Name: "usr/bin/ok", Uid: 1000, Gid: 1000}

	err := checkArchiveOwner(h)
	if math.MaxInt < math.MaxUint32 {
		require.ErrorContains(t, err, "requires a 64-bit build")
	} else {
		require.NoError(t, err)
	}

	// checkOwner itself must stay usable on every platform: AddInstalledPackage
	// calls it with headers a caller built, which archive/tar never touched.
	require.NoError(t, checkOwner(h), "checkOwner must not inherit the archive guard")
}

// TestInstallAPKFilesRejectsOutOfRangeOwner: archive/tar reads PAX uid/gid
// records into an int, so a crafted APK can declare an owner outside the
// uint32 range. The EROFS writer truncates to uint32, turning 2^32 into 0, so a
// 04755 file with uid 2^32 would come out setuid root. Such a header must fail
// the install rather than reach any Chown.
func TestInstallAPKFilesRejectsOutOfRangeOwner(t *testing.T) {
	skipWithoutOwnerValidation(t)
	// uid/gid are int64 here, not int: 1<<32 is an untyped constant that does
	// not fit an int where int is 32 bits, and goreleaser builds linux/386. The
	// rows that overflow are skipped there rather than made to compile, because
	// the scenario is unrepresentable in a tar.Header.Uid on that platform --
	// archive/tar rejects the value before any of this code sees it.
	cases := []struct {
		name     string
		uid, gid int64
		errMatch string
	}{
		{"uid 2^32", 1 << 32, 0, "invalid uid 4294967296"},
		{"negative uid", -1, 0, "invalid uid -1"},
		{"gid 2^32", 0, 1 << 32, "invalid gid 4294967296"},
		{"negative gid", 0, -1, "invalid gid -1"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			// Skip the test when the ids don't fit an int. On a 32-bit platform
			// archive/tar rejects it before this code sees it.
			uid, gid := idsAsIntOrSkip(t, tt.uid, tt.gid)

			apk, src, err := testGetTestAPK()
			require.NoError(t, err)

			var buf bytes.Buffer
			tw := tar.NewWriter(&buf)
			require.NoError(t, tw.WriteHeader(&tar.Header{Name: "usr", Typeflag: tar.TypeDir, Mode: 0o755}))
			require.NoError(t, tw.WriteHeader(&tar.Header{Name: "usr/bin", Typeflag: tar.TypeDir, Mode: 0o755}))
			content := []byte("#!/bin/sh\n")
			require.NoError(t, tw.WriteHeader(&tar.Header{
				Name:     "usr/bin/backdoor",
				Typeflag: tar.TypeReg,
				Mode:     0o4755,
				Uid:      uid,
				Gid:      gid,
				Size:     int64(len(content)),
			}))
			_, err = tw.Write(content)
			require.NoError(t, err)
			require.NoError(t, tw.Close())

			// Make sure the header really carries the out-of-range value and
			// archive/tar did not clamp or reject it on the way in; otherwise
			// this test would pass for the wrong reason.
			tr := tar.NewReader(bytes.NewReader(buf.Bytes()))
			for {
				hdr, err := tr.Next()
				require.NoError(t, err)
				if hdr.Name == "usr/bin/backdoor" {
					require.Equal(t, uid, hdr.Uid)
					require.Equal(t, gid, hdr.Gid)
					break
				}
			}

			_, err = apk.installAPKFiles(context.Background(), bytes.NewReader(buf.Bytes()), &Package{Origin: ""})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errMatch)

			_, err = src.Stat("usr/bin/backdoor")
			assert.ErrorIs(t, err, fs.ErrNotExist, "file with out-of-range owner must not be installed")
		})
	}
}

// TestInstallAPKFilesModesOnDisk is the same concern as
// TestInstallAPKFilesModesAndOwnership, against a disk-backed filesystem.
// Those strip setuid/setgid/sticky from the mode passed to MkdirAll and
// OpenFile, so the bits only reach the disk if we Chmod afterwards. Ownership
// is not asserted: Chown needs privileges the test does not have, and the
// filesystem tolerates the EPERM.
func TestInstallAPKFilesModesOnDisk(t *testing.T) {
	skipWithoutOwnerValidation(t)
	dir := t.TempDir()
	src := apkfs.DirFS(t.Context(), dir)
	require.NotNil(t, src)
	apk, err := New(t.Context(), WithFS(src), WithIgnoreMknodErrors(ignoreMknodErrors))
	require.NoError(t, err)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "var", Typeflag: tar.TypeDir, Mode: 0o755}))
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "var/spool", Typeflag: tar.TypeDir, Mode: 0o1777}))
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "postdrop", Typeflag: tar.TypeReg, Mode: 0o2755, Size: 8}))
	_, err = tw.Write([]byte("postdrop"))
	require.NoError(t, err)
	// A header owned by whoever runs the test is the one case where the disk
	// chown actually succeeds unprivileged, so this is the entry that reaches
	// the kernel's clearing of setgid on chown(2) rather than an EPERM the
	// filesystem swallows. It fails if Chmod is applied before Chown.
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name: "selfowned", Typeflag: tar.TypeReg, Mode: 0o2755,
		Uid: os.Getuid(), Gid: os.Getgid(), Size: 4,
	}))
	_, err = tw.Write([]byte("self"))
	require.NoError(t, err)
	require.NoError(t, tw.Close())

	_, err = apk.installAPKFiles(t.Context(), bytes.NewReader(buf.Bytes()), &Package{Origin: ""})
	require.NoError(t, err)

	for name, want := range map[string]fs.FileMode{
		"var/spool": fs.ModeDir | fs.ModeSticky | 0o777,
		"postdrop":  fs.ModeSetgid | 0o755,
		"selfowned": fs.ModeSetgid | 0o755,
	} {
		fi, err := os.Stat(filepath.Join(dir, name))
		require.NoError(t, err, "error statting %s", name)
		assert.Equal(t, want, fi.Mode(), "mismatched on-disk mode for %s", name)
	}
}

// orderRecordingFS records the order in which Chmod and Chown reach each path.
// It only records — every call still runs against the wrapped filesystem, so
// there is no emulated behavior here to drift out of sync with the real thing.
type orderRecordingFS struct {
	apkfs.FullFS

	mu    sync.Mutex
	calls map[string][]string
}

func newOrderRecordingFS(inner apkfs.FullFS) *orderRecordingFS {
	return &orderRecordingFS{FullFS: inner, calls: map[string][]string{}}
}

func (o *orderRecordingFS) record(path, op string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls[path] = append(o.calls[path], op)
}

func (o *orderRecordingFS) ops(path string) []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.calls[path])
}

func (o *orderRecordingFS) Chmod(path string, perm fs.FileMode) error {
	o.record(path, "chmod")
	return o.FullFS.Chmod(path, perm)
}

func (o *orderRecordingFS) Chown(path string, uid, gid int) error {
	o.record(path, "chown")
	return o.FullFS.Chown(path, uid, gid)
}

// TestInstallAPKFilesMetadataOrder pins Chown before Chmod. chown(2) on a
// regular file clears setuid/setgid — for root too — so chowning after the
// Chmod that restores those bits drops them again on any filesystem that
// writes through to disk. No unprivileged test can observe that: dirFS
// tolerates the EPERM from the disk chown and never reaches the kernel
// behavior, so the call order is pinned here instead.
func TestInstallAPKFilesMetadataOrder(t *testing.T) {
	skipWithoutOwnerValidation(t)
	rec := newOrderRecordingFS(apkfs.NewMemFS())
	apk, err := New(t.Context(), WithFS(rec), WithIgnoreMknodErrors(ignoreMknodErrors))
	require.NoError(t, err)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "var", Typeflag: tar.TypeDir, Mode: 0o755}))
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "var/spool", Typeflag: tar.TypeDir, Mode: 0o1777}))
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "postdrop", Typeflag: tar.TypeReg, Mode: 0o2755, Gid: 101, Size: 8}))
	_, err = tw.Write([]byte("postdrop"))
	require.NoError(t, err)
	require.NoError(t, tw.Close())

	_, err = apk.installAPKFiles(t.Context(), bytes.NewReader(buf.Bytes()), &Package{Origin: ""})
	require.NoError(t, err)

	// The setgid file is the case the kernel would bite; the sticky directory
	// is here so the two paths cannot drift apart unnoticed.
	for _, name := range []string{"postdrop", "var/spool"} {
		assert.Equal(t, []string{"chown", "chmod"}, rec.ops(name),
			"metadata calls for %s must be chown then chmod", name)
	}
}

// mkdirRecordingFS records the paths MkdirAll is asked for. Whether the
// symlink survives is not enough on its own to pin the behavior: MkdirAll over
// a path that already resolves to a directory is a no-op on an in-memory
// filesystem, so the symlink is still there either way. What the tar.TypeDir
// branch decides is whether MkdirAll is reached at all.
type mkdirRecordingFS struct {
	apkfs.FullFS

	mu    sync.Mutex
	paths []string
}

func (m *mkdirRecordingFS) MkdirAll(path string, perm fs.FileMode) error {
	m.mu.Lock()
	m.paths = append(m.paths, path)
	m.mu.Unlock()
	return m.FullFS.MkdirAll(path, perm)
}

func (m *mkdirRecordingFS) made() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.paths)
}

// TestInstallAPKFilesKeepsSymlinkToDirectory covers the case the tar.TypeDir
// branch already meant to handle: a package ships a directory header for a
// path the image carries as a symlink to a directory, and the symlink has to
// be accepted as is. The check reached for that through Stat, which resolves
// the final component and so never reports ModeSymlink, leaving the branch
// unreachable and sending every such path to MkdirAll instead.
//
// The layout is the merged-usr one apko creates for itself in InitDB: usr/lib
// is the directory, lib is a symlink to it.
func TestInstallAPKFilesKeepsSymlinkToDirectory(t *testing.T) {
	mem := apkfs.NewMemFS()
	require.NoError(t, mem.MkdirAll("usr/lib", 0o755))
	require.NoError(t, mem.Symlink("usr/lib", "lib"))

	before, err := mem.Lstat("lib")
	require.NoError(t, err)
	require.NotZero(t, before.Mode()&fs.ModeSymlink, "setup: lib has to start out as a symlink")

	rec := &mkdirRecordingFS{FullFS: mem}
	apk, err := New(t.Context(), WithFS(rec), WithIgnoreMknodErrors(ignoreMknodErrors))
	require.NoError(t, err)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "lib", Typeflag: tar.TypeDir, Mode: 0o755}))
	require.NoError(t, tw.Close())

	_, err = apk.installAPKFiles(t.Context(), bytes.NewReader(buf.Bytes()), &Package{Origin: ""})
	require.NoError(t, err)

	assert.NotContains(t, rec.made(), "lib",
		"an existing symlink to a directory has to be accepted as is, without reaching MkdirAll")

	after, err := mem.Lstat("lib")
	require.NoError(t, err)
	assert.NotZero(t, after.Mode()&fs.ModeSymlink,
		"lib must still be a symlink after a directory header is installed over it")

	target, err := mem.Readlink("lib")
	require.NoError(t, err)
	assert.Equal(t, "usr/lib", target, "lib must still point at the directory it did before")
}

// TestLazilyInstallAPKFilesRejectsOutOfRangeOwner is the companion to
// TestInstallAPKFilesRejectsOutOfRangeOwner on the path apko build actually
// takes: installPackage dispatches to lazilyInstallAPKFiles whenever the
// filesystem is a WriteHeaderer, which pkg/tarfs is, and which is what
// apko build, apko publish and apko build-minirootfs all construct. The
// headers this returns go on to AddInstalledPackage, so an out-of-range owner
// has to be refused before the entry is written rather than recorded and
// rejected later by the read side.
func TestLazilyInstallAPKFilesRejectsOutOfRangeOwner(t *testing.T) {
	skipWithoutOwnerValidation(t)
	cases := []struct {
		name     string
		uid, gid int64
		errMatch string
	}{
		{"uid 2^32", 1 << 32, 0, "invalid uid 4294967296"},
		{"negative uid", -1, 0, "invalid uid -1"},
		{"gid 2^32", 0, 1 << 32, "invalid gid 4294967296"},
		{"negative gid", 0, -1, "invalid gid -1"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			// Skip the test when the ids don't fit an int. On a 32-bit platform
			// archive/tar rejects it before this code sees it.
			uid, gid := idsAsIntOrSkip(t, tt.uid, tt.gid)

			apk, _, err := testGetTestAPK()
			require.NoError(t, err)

			entries := []tar.Header{
				{Name: "usr", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "usr/bin", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "usr/bin/backdoor", Typeflag: tar.TypeReg, Mode: 0o4755, Uid: uid, Gid: gid, Size: 10},
			}

			wh := &recordingWriteHeaderer{}
			_, err = apk.lazilyInstallAPKFiles(t.Context(), wh, entries, fstest.MapFS{}, &Package{Name: "backdoor"})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errMatch)
			assert.NotContains(t, wh.written, "usr/bin/backdoor", "entry with out-of-range owner must not be written")
		})
	}
}
