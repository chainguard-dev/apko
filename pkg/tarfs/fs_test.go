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

package tarfs_test

import (
	"archive/tar"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/apk/apk"

	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/tarfs"
)

func TestTarFS(t *testing.T) {
	tfs := tarfs.New()
	ctx := context.Background()

	opts := []build.Option{
		// Keep the disk cache and scratch files out of the user's cache
		// directory and $TMPDIR.
		build.WithCache(t.TempDir(), false, apk.NewCache(false)),
		build.WithTempDir(t.TempDir()),
		build.WithConfig(filepath.Join("testdata", "apko.yaml"), []string{}),
	}

	bc, err := build.New(ctx, tfs, opts...)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := bc.BuildLayer(ctx); err != nil {
		t.Fatal(err)
	}

	installed, err := bc.InstalledPackages()
	if err != nil {
		t.Fatal(err)
	}

	// Check that everything in installed was written.
	for _, pkg := range installed {
		for _, hdr := range pkg.Files {
			// It should exist at least.
			stat, err := tfs.Stat(hdr.Name)
			if err != nil {
				t.Errorf("stat file %q: %v", hdr.Name, err)
				continue
			}

			if stat.Size() == 0 {
				continue
			}

			if _, err := tfs.Open(hdr.Name); err != nil {
				t.Errorf("opening %q: %v", hdr.Name, err)
			}
		}
	}

	// Pull a file out of the apk that we know exists and hit a bunch of edge cases.
	pkg := installed[1]
	want := "etc/os-release"
	var file *tar.Header
	for _, hdr := range pkg.Files {
		if hdr.Name == want {
			file = &hdr
			break
		}
	}
	if file == nil {
		t.Fatalf("did not find %q", want)
		return
	}
	file.Typeflag = tar.TypeReg

	if _, err := tfs.WriteHeader(*file, tfs, &pkg.Package); err == nil {
		t.Errorf("wanted missing checksum err, got nil")
	}

	otherPkg := &apk.Package{Origin: "different", Name: "different"}

	// # https://github.com/jonjohnsonjr/tarp
	// $ cat internal/cli/testdata/packages/aarch64/replayout-1.0.0-r0.apk | gunzip | tarp | grep "etc/os-release" | jq .PAXRecords -c
	// {"APK-TOOLS.checksum.SHA1":"ca5e527bbb8a5cc9c4c2d2b4e29618d8ca3be5f8"}
	file.PAXRecords = map[string]string{
		"APK-TOOLS.checksum.SHA1": "ca5e527bbb8a5cc9c4c2d2b4e29618d8ca3be5f8",
	}
	if _, err := tfs.WriteHeader(*file, tfs, otherPkg); err != nil {
		t.Errorf("matching checksum should be skipped, got %v", err)
	}

	file.PAXRecords = map[string]string{
		"APK-TOOLS.checksum.SHA1": "0000000000000000000000000000000000000000",
	}
	if _, err := tfs.WriteHeader(*file, tfs, otherPkg); err == nil {
		t.Errorf("wanted conflicting checksum err, got nil")
	}

	otherPkg.Replaces = []string{pkg.Name}
	if _, err := tfs.WriteHeader(*file, tfs, otherPkg); err != nil {
		t.Errorf("pkg replaces file, got %v", err)
	}

	// Ensure that symlinks work with replaces.
	{
		original := tar.Header{
			Name:     "etc/os-release-symlink",
			Typeflag: tar.TypeSymlink,
			Linkname: "etc/os-release-symlink",
		}
		originalDigest := sha1.Sum([]byte(original.Linkname)) //nolint:gosec
		originalChecksum := hex.EncodeToString(originalDigest[:])
		original.PAXRecords = map[string]string{
			"APK-TOOLS.checksum.SHA1": originalChecksum,
		}

		if _, err := tfs.WriteHeader(original, tfs, &pkg.Package); err != nil {
			t.Fatalf("symlinking: %v", err)
		}

		link := tar.Header{
			Name:     "etc/os-release-symlink",
			Typeflag: tar.TypeSymlink,
			Linkname: "etc/somewhere-else",
		}
		linkDigest := sha1.Sum([]byte(link.Linkname)) //nolint:gosec
		linkChecksum := hex.EncodeToString(linkDigest[:])
		link.PAXRecords = map[string]string{
			"APK-TOOLS.checksum.SHA1": linkChecksum,
		}

		if _, err := tfs.WriteHeader(link, tfs, otherPkg); err != nil {
			t.Errorf("pkg replaces symlink, got %v", err)
		}

		target, err := tfs.Readlink(link.Name)
		if err != nil {
			t.Fatal(err)
		}

		if want, got := "etc/somewhere-else", target; want != got {
			t.Errorf("readlink: want %q, got %q", want, got)
		}
	}
}

func TestTarFSCreate(t *testing.T) {
	var (
		tfs = tarfs.New()
		err error
	)
	fd, err := tfs.Create("testfile")
	require.NoError(t, err)

	fileInfo, err := fd.Stat()
	require.NoError(t, err)
	require.Equal(t, fileInfo.Mode(), fs.FileMode(0o644))
}

// TestTarFSTruncatePackageFile checks that a package file truncated through
// OpenFile is empty from then on, rather than the package's content again.
func TestTarFSTruncatePackageFile(t *testing.T) {
	content := []byte("the package's content\n")
	sum := sha1.Sum(content) //nolint:gosec // APK per-file checksums are SHA-1
	src := fstest.MapFS{"etc/conf": {Data: content, Mode: 0o644}}
	hdr := tar.Header{
		Typeflag:   tar.TypeReg,
		Name:       "etc/conf",
		Mode:       0o644,
		Size:       int64(len(content)),
		PAXRecords: map[string]string{"APK-TOOLS.checksum.SHA1": hex.EncodeToString(sum[:])},
	}
	m := tarfs.New()
	require.NoError(t, m.MkdirAll("etc", 0o755))
	_, err := m.WriteHeader(hdr, src, &apk.Package{Name: "p", Origin: "p"})
	require.NoError(t, err)

	f, err := m.OpenFile("etc/conf", os.O_WRONLY|os.O_TRUNC, 0o644)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	got, err := m.ReadFile("etc/conf")
	require.NoError(t, err)
	require.Empty(t, got)
	info, err := m.Stat("etc/conf")
	require.NoError(t, err)
	require.Zero(t, info.Size())
}

func TestTarFSPackageFileReadFailure(t *testing.T) {
	content := []byte("the package's content\n")
	sum := sha1.Sum(content) //nolint:gosec // APK per-file checksums are SHA-1
	base := fstest.MapFS{"etc/conf": {Data: content, Mode: 0o644}}
	readErr := errors.New("backing read failed")
	src := &failFirstReadFS{FS: base, err: readErr}
	hdr := tar.Header{
		Typeflag:   tar.TypeReg,
		Name:       "etc/conf",
		Mode:       0o644,
		Size:       int64(len(content)),
		PAXRecords: map[string]string{"APK-TOOLS.checksum.SHA1": hex.EncodeToString(sum[:])},
	}
	m := tarfs.New()
	require.NoError(t, m.MkdirAll("etc", 0o755))
	_, err := m.WriteHeader(hdr, src, &apk.Package{Name: "p", Origin: "p"})
	require.NoError(t, err)

	_, err = m.OpenFile("etc/conf", os.O_RDWR, 0o644)
	require.ErrorIs(t, err, readErr)

	got, err := m.ReadFile("etc/conf")
	require.NoError(t, err)
	require.Equal(t, content, got)
	info, err := m.Stat("etc/conf")
	require.NoError(t, err)
	require.Equal(t, int64(len(content)), info.Size())

	f, err := m.OpenFile("etc/conf", os.O_RDWR, 0o644)
	require.NoError(t, err)
	n, err := f.Write([]byte("new"))
	require.NoError(t, err)
	require.Equal(t, 3, n)
	require.NoError(t, f.Close())

	got, err = m.ReadFile("etc/conf")
	require.NoError(t, err)
	require.Equal(t, "new"+string(content[3:]), string(got))
	got, err = fs.ReadFile(base, "etc/conf")
	require.NoError(t, err)
	require.Equal(t, content, got)
}

type failFirstReadFS struct {
	fs.FS
	err error
}

func (f *failFirstReadFS) Open(name string) (fs.File, error) {
	file, err := f.FS.Open(name)
	if err != nil {
		return nil, err
	}
	if f.err != nil {
		err := f.err
		f.err = nil
		return &failedReadFile{File: file, err: err}, nil
	}
	return file, nil
}

type failedReadFile struct {
	fs.File
	err error
}

func (f *failedReadFile) Read([]byte) (int, error) {
	return 0, f.err
}

// TestTarFSLchown checks that Lchown re-owns a symlink itself rather than its
// target, including for a dangling link and a path with a trailing slash.
func TestTarFSLchown(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		wantErr    bool
	}{
		{name: "link", path: "/home/link"},
		{name: "trailing slash", path: "/home/link/"},
		{name: "dangling", path: "/home/dangling"},
		{name: "regular file", path: "/etc/link"},
		{name: "missing", path: "/home/missing", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := tarfs.New()
			require.NoError(t, m.MkdirAll("/etc", 0o755))
			require.NoError(t, m.WriteFile("/etc/link", []byte("x"), 0o644))
			require.NoError(t, m.MkdirAll("/home", 0o755))
			require.NoError(t, m.Symlink("/etc", "/home/link"))
			require.NoError(t, m.Symlink("/does/not/exist", "/home/dangling"))

			err := m.Lchown(tc.path, 999, 998)
			if tc.wantErr {
				require.ErrorIs(t, err, fs.ErrNotExist)
				return
			}
			require.NoError(t, err)

			owners := map[string][2]int{}
			for _, dir := range []string{"/etc", "/home"} {
				des, err := m.ReadDir(dir)
				require.NoError(t, err)
				for _, de := range des {
					info, err := de.Info()
					require.NoError(t, err)
					hdr, ok := info.Sys().(*tar.Header)
					require.True(t, ok)
					owners[filepath.Join(dir, de.Name())] = [2]int{hdr.Uid, hdr.Gid}
				}
			}
			want := filepath.Clean(tc.path)
			for path, got := range owners {
				if path == want {
					require.Equal(t, [2]int{999, 998}, got, "owner of %s", path)
				} else {
					require.Equal(t, [2]int{0, 0}, got, "owner of %s changed", path)
				}
			}
			require.Contains(t, owners, want)
		})
	}
}

// digestingFS names each entry's content by digest, as an
// apk.ContentDigester.
type digestingFS struct {
	fstest.MapFS
	digests map[string]string
}

func (d digestingFS) ContentDigest(name string) (string, bool) {
	dg, ok := d.digests[name]
	return dg, ok
}

func TestContentDigest(t *testing.T) {
	const content = "package content"
	sum := sha1.Sum([]byte(content)) //nolint:gosec
	reg := func(name string) tar.Header {
		return tar.Header{
			Typeflag:   tar.TypeReg,
			Name:       name,
			Mode:       0o644,
			Size:       int64(len(content)),
			PAXRecords: map[string]string{"APK-TOOLS.checksum.SHA1": hex.EncodeToString(sum[:])},
		}
	}
	names := []string{"kept", "chmodded", "chowned", "rewritten", "appended", "opened-rw", "removed", "nodigest", "plain-source"}
	src := digestingFS{MapFS: fstest.MapFS{}, digests: map[string]string{}}
	plain := fstest.MapFS{}
	for _, n := range names {
		src.MapFS[n] = &fstest.MapFile{Data: []byte(content)}
		plain[n] = &fstest.MapFile{Data: []byte(content)}
		if n != "nodigest" {
			src.digests[n] = "test:" + n
		}
	}
	pkg := &apk.Package{Name: "p", Origin: "p"}

	m := tarfs.New()
	for _, n := range names {
		var from fs.FS = src
		if n == "plain-source" {
			from = plain
		}
		if _, err := m.WriteHeader(reg(n), from, pkg); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{"kept-link": "kept", "appended-link": "appended"} {
		if _, err := m.WriteHeader(tar.Header{Typeflag: tar.TypeLink, Name: link, Linkname: target}, src, pkg); err != nil {
			t.Fatal(err)
		}
	}
	m.WriteFile("created", []byte(content), 0o644) //nolint:errcheck

	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(m.Chmod("chmodded", 0o600))
	must(m.Chown("chowned", 1000, 1000))
	must(m.WriteFile("rewritten", []byte("other"), 0o644))
	f, err := m.OpenFile("appended", os.O_WRONLY|os.O_APPEND, 0o644)
	must(err)
	_, err = f.Write([]byte("more"))
	must(err)
	must(f.Close())
	// Opened to be modified, but nothing written: its content is now held in
	// memory, so it is hashed rather than taken from the package.
	f, err = m.OpenFile("opened-rw", os.O_RDWR, 0o644)
	must(err)
	must(f.Close())
	must(m.Remove("removed"))
	must(m.WriteFile("removed", []byte(content), 0o644))
	must(m.MkdirAll("dir", 0o755))

	sha256Of := func(s string) string {
		sum := sha256.Sum256([]byte(s))
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	// Non-empty regular files use the supplied digest while backed by the
	// package, and SHA-256 otherwise. Directories return an empty digest.
	for name, want := range map[string]string{
		"kept":          "test:kept",
		"chmodded":      "test:chmodded",
		"chowned":       "test:chowned",
		"rewritten":     sha256Of("other"),
		"appended":      sha256Of(content + "more"),
		"kept-link":     "test:kept",
		"appended-link": sha256Of(content + "more"),
		"opened-rw":     sha256Of(content),
		"removed":       sha256Of(content),
		"nodigest":      sha256Of(content),
		"plain-source":  sha256Of(content),
		"created":       sha256Of(content),
		"dir":           "",
	} {
		info, err := m.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		got, err := info.(interface{ ContentDigest() (string, error) }).ContentDigest()
		if err != nil || got != want {
			t.Errorf("%s: ContentDigest() = %q, %v; want %q", name, got, err, want)
		}
	}
}
