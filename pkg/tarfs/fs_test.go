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
	"encoding/hex"
	"io/fs"
	"path"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/apk/apk"

	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/tarfs"
)

func TestTarFS(t *testing.T) {
	tfs := tarfs.New()
	ctx := context.Background()

	opts := []build.Option{
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

// dirReader is implemented by the (unexported) tarfs type returned by New().
type dirReader interface {
	ReadDir(string) ([]fs.DirEntry, error)
	Readlink(string) (string, error)
}

// outHeader returns the tar.Header that pkg/build/tarball.go would write for
// name. It reaches the entry the way that writer does -- a directory walk,
// then tar.FileInfoHeader -- because that is how a node's metadata reaches
// both the tar and the erofs writer.
func outHeader(t *testing.T, tfs dirReader, name string) *tar.Header {
	t.Helper()
	entries, err := tfs.ReadDir(path.Dir(name))
	require.NoError(t, err)
	for _, d := range entries {
		if d.Name() != path.Base(name) {
			continue
		}
		info, err := d.Info()
		require.NoError(t, err)
		var link string
		if info.Mode()&fs.ModeSymlink != 0 {
			// tarball.go passes the link target for symlinks.
			link, err = tfs.Readlink(name)
			require.NoError(t, err)
		}
		hdr, err := tar.FileInfoHeader(info, link)
		require.NoError(t, err)
		return hdr
	}
	t.Fatalf("no entry for %q", name)
	return nil
}

// TestWriteHeaderDirMetadata covers a directory header's setuid/setgid/sticky
// bits and ownership, which MkdirAll alone does not carry.
func TestWriteHeaderDirMetadata(t *testing.T) {
	tfs := tarfs.New()
	pkg := &apk.Package{Name: "postfix", Origin: "postfix"}

	// Mode as apk-tools would record 2755 with the sticky bit also set.
	dir := tar.Header{
		Typeflag: tar.TypeDir,
		Name:     "var/spool/postfix/maildrop",
		Mode:     0o2755 | 0o1000,
		Uid:      100,
		Gid:      101,
	}
	if _, err := tfs.WriteHeader(dir, tfs, pkg); err != nil {
		t.Fatal(err)
	}

	fi, err := tfs.Lstat(dir.Name)
	require.NoError(t, err)
	require.Equal(t, fs.ModeDir|fs.ModeSetgid|fs.ModeSticky|0o755, fi.Mode())

	hdr := outHeader(t, tfs, dir.Name)
	require.Equal(t, dir.Mode, hdr.Mode)
	require.Equal(t, 100, hdr.Uid)
	require.Equal(t, 101, hdr.Gid)

	// Ancestors MkdirAll had to invent are not owned by the header, so they
	// must not pick up its ownership.
	for _, ancestor := range []string{"var", "var/spool", "var/spool/postfix"} {
		hdr := outHeader(t, tfs, ancestor)
		require.Zerof(t, hdr.Uid, "uid of implicit ancestor %q", ancestor)
		require.Zerof(t, hdr.Gid, "gid of implicit ancestor %q", ancestor)
	}
}

// TestWriteHeaderDirExisting guards the /tmp case: apk's InitDB creates /tmp
// as 1777 before any package installs, and packages ship a tmp header with no
// sticky bit, so a header for a directory that is already there must not
// downgrade it.
func TestWriteHeaderDirExisting(t *testing.T) {
	tfs := tarfs.New()
	pkg := &apk.Package{Name: "wolfi-baselayout", Origin: "wolfi-baselayout"}

	require.NoError(t, tfs.Mkdir("tmp", fs.ModeSticky|0o777))

	dir := tar.Header{
		Typeflag: tar.TypeDir,
		Name:     "tmp",
		Mode:     0o777,
		Uid:      100,
		Gid:      100,
	}
	if _, err := tfs.WriteHeader(dir, tfs, pkg); err != nil {
		t.Fatal(err)
	}

	fi, err := tfs.Lstat("tmp")
	require.NoError(t, err)
	require.Equal(t, fs.ModeDir|fs.ModeSticky|0o777, fi.Mode())

	hdr := outHeader(t, tfs, "tmp")
	require.Equal(t, int64(0o1777), hdr.Mode)
	require.Zero(t, hdr.Uid)
	require.Zero(t, hdr.Gid)
}
