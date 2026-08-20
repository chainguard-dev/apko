// Copyright 2026 Chainguard, Inc.
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

package build

import (
	"archive/tar"
	"context"
	"crypto/sha1" //nolint:gosec // the checksum tarfs verifies is apk's, which is SHA-1
	"encoding/hex"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"testing/fstest"

	erofs "github.com/erofs/go-erofs"
	"github.com/stretchr/testify/require"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/tarfs"
)

// linkedFile is the one real file every fixture below builds its extra names
// on top of.
const linkedFile = "usr/bin/coreutils"

// hardlinkFS builds a pkg/tarfs holding linkedFile plus `links` extra names for
// it, the way apk installs a package whose tar carries TypeLink entries.
//
// It has to be pkg/tarfs: apkfs.MemFS has a Link method, but its FileInfo.Sys()
// returns a bare *tar.Header with no Typeflag or Linkname, so a hardlink there
// is indistinguishable from two separate files and the writer would copy the
// data either way.
func hardlinkFS(t *testing.T, data string, links ...string) apkfs.FullFS {
	t.Helper()

	target := linkedFile

	m := tarfs.New()
	require.NoError(t, m.MkdirAll(filepath.Dir(target), 0o755))

	sum := sha1.Sum([]byte(data)) //nolint:gosec // see the import comment
	_, err := m.WriteHeader(tar.Header{
		Typeflag: tar.TypeReg,
		Name:     target,
		Size:     int64(len(data)),
		Mode:     0o755,
		ModTime:  epoch,
		PAXRecords: map[string]string{
			"APK-TOOLS.checksum.SHA1": hex.EncodeToString(sum[:]),
		},
	}, fstest.MapFS{target: &fstest.MapFile{Data: []byte(data), Mode: 0o755}}, nil)
	require.NoError(t, err)

	for _, l := range links {
		require.NoError(t, m.MkdirAll(filepath.Dir(l), 0o755))
		_, err := m.WriteHeader(tar.Header{
			Typeflag: tar.TypeLink,
			Name:     l,
			Linkname: target,
			Mode:     0o755,
			ModTime:  epoch,
		}, nil, nil)
		require.NoError(t, err, "linking %s -> %s", l, target)
	}
	return m
}

func openImage(t *testing.T, path string) fs.FS {
	t.Helper()

	f, err := os.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	img, err := erofs.Open(f)
	require.NoError(t, err)
	return img
}

func statOf(t *testing.T, img fs.FS, name string) *erofs.Stat {
	t.Helper()

	info, err := fs.Stat(img, name)
	require.NoError(t, err, "stat %s", name)
	st, ok := info.Sys().(*erofs.Stat)
	require.True(t, ok, "expected *erofs.Stat on %s Sys()", name)
	return st
}

func TestWriteErofs_HardlinksShareOneInode(t *testing.T) {
	// "[" sorts before "coreutils", so fs.WalkDir hands the link to the writer
	// before the file it points at. That ordering is the reason links are held
	// back until the walk is done.
	const data = "not really a binary, but long enough to occupy a block\n"
	m := hardlinkFS(t, data, "usr/bin/[", "usr/bin/yes")

	out := filepath.Join(t.TempDir(), "image.erofs")
	f, err := os.Create(out)
	require.NoError(t, err)
	require.NoError(t, writeErofs(context.Background(), f, m, t.TempDir(), epoch))
	require.NoError(t, f.Close())

	img := openImage(t, out)

	names := []string{"usr/bin/coreutils", "usr/bin/[", "usr/bin/yes"}
	for _, name := range names {
		content, err := fs.ReadFile(img, name)
		require.NoError(t, err, "reading %s", name)
		require.Equal(t, data, string(content), "content mismatch for %s", name)
	}

	// One inode, three names. Before Writer.Link this was three inodes, each
	// with its own copy of the data.
	want := statOf(t, img, "usr/bin/coreutils")
	require.EqualValues(t, len(names), want.Nlink, "link count")
	for _, name := range names[1:] {
		require.Equal(t, want.Ino, statOf(t, img, name).Ino, "%s does not share the inode", name)
	}

	// Mode and ownership come with the shared inode, so the link names must
	// report what the target had rather than a default.
	require.Equal(t, fs.FileMode(0o755), statOf(t, img, "usr/bin/[").Mode.Perm())

	if fsckBin := optionalFsckErofs(t); fsckBin != "" {
		output, err := exec.Command(fsckBin, "-d3", out).CombinedOutput()
		require.NoError(t, err, "fsck.erofs rejected the image:\n%s", output)
	}
}

// TestWriteErofs_HardlinksCostOneCopy pins the reason for doing this at all:
// the data is stored once no matter how many names point at it.
func TestWriteErofs_HardlinksCostOneCopy(t *testing.T) {
	// Comfortably more than one 4K block, so a second copy cannot hide in
	// padding.
	data := string(make([]byte, 64*1024))

	build := func(links ...string) int64 {
		t.Helper()
		out := filepath.Join(t.TempDir(), "image.erofs")
		f, err := os.Create(out)
		require.NoError(t, err)
		require.NoError(t, writeErofs(context.Background(), f, hardlinkFS(t, data, links...), t.TempDir(), epoch))
		require.NoError(t, f.Close())
		fi, err := os.Stat(out)
		require.NoError(t, err)
		return fi.Size()
	}

	alone := build()
	withLinks := build("usr/bin/[", "usr/bin/yes", "usr/bin/true")

	// Three more dirents and inodes cost a little metadata; three more copies
	// of a 64K file would cost 192K.
	require.Less(t, withLinks-alone, int64(32*1024),
		"three hardlinks grew the image by %d bytes, which looks like copied data", withLinks-alone)
}

// TestEmitErofsHardlinks_MaterializesWhenTargetIsAbsent covers the cross-layer
// case from spec §3.7: a link whose target is not in this image cannot share
// an inode with it, so it gets a copy of its own instead of failing the build.
// Splitting a rootfs across layers is what puts a link and its target in
// different images.
func TestEmitErofsHardlinks_MaterializesWhenTargetIsAbsent(t *testing.T) {
	const data = "payload\n"
	m := hardlinkFS(t, data, "usr/bin/[")

	info, err := fs.Stat(m, "usr/bin/[")
	require.NoError(t, err)
	target, ok := hardlinkTarget(info)
	require.True(t, ok, "fixture did not record usr/bin/[ as a hardlink")
	require.Equal(t, linkedFile, target)

	// A writer that has the parent directory but never received the target.
	out := filepath.Join(t.TempDir(), "image.erofs")
	f, err := os.Create(out)
	require.NoError(t, err)
	w := erofs.Create(f, erofs.WithBuildTime(0, 0))
	require.NoError(t, w.Mkdir("/usr", 0o755))
	require.NoError(t, w.Mkdir("/usr/bin", 0o755))

	links := []erofsHardlink{{path: "usr/bin/[", target: target, info: info}}
	require.NoError(t, emitErofsHardlinks(context.Background(), w, links, m, make([]byte, 1<<20)))
	require.NoError(t, w.Close())
	require.NoError(t, f.Close())

	img := openImage(t, out)
	content, err := fs.ReadFile(img, "usr/bin/[")
	require.NoError(t, err, "the link was neither shared nor materialized")
	require.Equal(t, data, string(content))
	require.Equal(t, fs.FileMode(0o755), statOf(t, img, "usr/bin/[").Mode.Perm())

	// Nothing to share with, so it is a standalone file.
	_, err = fs.Stat(img, "usr/bin/coreutils")
	require.Error(t, err, "the target should not be in this image")
}

func TestHardlinkTarget(t *testing.T) {
	regular := hardlinkFS(t, "x")
	info, err := fs.Stat(regular, "usr/bin/coreutils")
	require.NoError(t, err)
	_, ok := hardlinkTarget(info)
	require.False(t, ok, "the file a link points at must not itself look like a link")

	// apkfs.MemFS cannot express a hardlink, which is why the fixtures above
	// use pkg/tarfs.
	mem := apkfs.NewMemFS()
	require.NoError(t, mem.MkdirAll("usr/bin", 0o755))
	require.NoError(t, mem.WriteFile("usr/bin/coreutils", []byte("x"), 0o755))
	require.NoError(t, mem.Link("usr/bin/coreutils", "usr/bin/["))
	memInfo, err := fs.Stat(mem, "usr/bin/[")
	require.NoError(t, err)
	_, ok = hardlinkTarget(memInfo)
	require.False(t, ok, "apkfs.MemFS reports linkness after all; the writer could use it")

	// A Linkname is package metadata, so it is cleaned before use.
	for _, tc := range []struct{ linkname, want string }{
		{"usr/bin/coreutils", "usr/bin/coreutils"},
		{"/usr/bin/coreutils", "usr/bin/coreutils"},
		{"./usr/bin/../bin/coreutils", "usr/bin/coreutils"},
	} {
		got, ok := hardlinkTarget(&fakeInfo{sys: &tar.Header{Typeflag: tar.TypeLink, Linkname: tc.linkname}})
		require.True(t, ok, "%q", tc.linkname)
		require.Equal(t, tc.want, got, "%q", tc.linkname)
	}
}

// fakeInfo is the smallest fs.FileInfo that can carry a chosen Sys().
type fakeInfo struct {
	fs.FileInfo
	sys any
}

func (f *fakeInfo) Sys() any { return f.sys }
