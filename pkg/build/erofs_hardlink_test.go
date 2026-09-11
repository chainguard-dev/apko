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

	"chainguard.dev/apko/pkg/apk/apk"
	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/tarfs"
)

// linkedFile is the one real file every fixture below builds its extra names
// on top of, along with the metadata a link name has to inherit from it.
const (
	linkedFile = "usr/bin/coreutils"
	linkedUID  = 1234
	linkedGID  = 5678
	linkedAttr = "user.apko.test"
	linkedVal  = "from the target inode"
)

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
		Uid:      linkedUID,
		Gid:      linkedGID,
		PAXRecords: map[string]string{
			"APK-TOOLS.checksum.SHA1":    hex.EncodeToString(sum[:]),
			"SCHILY.xattr." + linkedAttr: linkedVal,
		},
	}, fstest.MapFS{target: &fstest.MapFile{Data: []byte(data), Mode: 0o755}}, nil)
	require.NoError(t, err)
	// WriteHeader does not carry Uid/Gid onto the node; apk chowns separately.
	require.NoError(t, m.Chown(target, linkedUID, linkedGID))

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

	// Everything hanging off the inode -- mode, ownership, xattrs -- comes
	// with it, so every link name must report what the target had rather
	// than a writer default (0644, uid 0, no xattrs).
	for _, name := range names {
		st := statOf(t, img, name)
		require.Equal(t, fs.FileMode(0o755), st.Mode.Perm(), "mode of %s", name)
		require.EqualValues(t, linkedUID, st.UID, "uid of %s", name)
		require.EqualValues(t, linkedGID, st.GID, "gid of %s", name)
		require.Equal(t, linkedVal, st.Xattrs[linkedAttr], "xattr of %s", name)
	}

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

// TestEmitErofsHardlinks_MaterializesWhenTargetIsAbsent covers the fallback
// spec §3.7 leaves to the producer: a link whose target is not in this image
// cannot share an inode with it, so it gets a copy of its own rather than
// failing the build. A `paths` directive removing the target, and a chain of
// links whose middle name is still deferred, both reach it.
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

// TestEmitErofsHardlinks_DirectoryTargetAborts pins the other side of the
// fallback: only a target the writer cannot find degrades to a copy. A
// Linkname resolving to a directory is a real error and stops the build,
// which is what link(2) does with one.
func TestEmitErofsHardlinks_DirectoryTargetAborts(t *testing.T) {
	m := hardlinkFS(t, "payload\n", "usr/bin/[")
	info, err := fs.Stat(m, "usr/bin/[")
	require.NoError(t, err)

	f, err := os.Create(filepath.Join(t.TempDir(), "image.erofs"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })
	w := erofs.Create(f, erofs.WithBuildTime(0, 0))
	require.NoError(t, w.Mkdir("/usr", 0o755))
	require.NoError(t, w.Mkdir("/usr/bin", 0o755))
	// The target path holds a directory rather than the file the link wants.
	// tarfs does not reject such a Linkname at unpack, so it gets this far.
	require.NoError(t, w.Mkdir("/usr/bin/coreutils", 0o755))

	links := []erofsHardlink{{path: "usr/bin/[", target: linkedFile, info: info}}
	err = emitErofsHardlinks(context.Background(), w, links, m, make([]byte, 1<<20))
	require.Error(t, err, "a directory target must not be copied over silently")
	require.ErrorIs(t, err, erofs.ErrIsDirectory)
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

	// A Linkname is package metadata, so it is cleaned before use, and one
	// that still points outside the image after that is not treated as a
	// link at all -- the writer would silently re-root it onto a real path.
	for _, tc := range []struct {
		linkname string
		want     string
		wantOK   bool
	}{
		{"usr/bin/coreutils", "usr/bin/coreutils", true},
		{"/usr/bin/coreutils", "usr/bin/coreutils", true},
		{"./usr/bin/../bin/coreutils", "usr/bin/coreutils", true},
		// Rooted, so the Clean absorbs the ".." the way the kernel would.
		{"/../etc/passwd", "etc/passwd", true},
		{"../etc/passwd", "", false},
		{"usr/bin/../../../etc/passwd", "", false},
		{"..", "", false},
	} {
		got, ok := hardlinkTarget(&fakeInfo{sys: &tar.Header{Typeflag: tar.TypeLink, Linkname: tc.linkname}})
		require.Equal(t, tc.wantOK, ok, "%q", tc.linkname)
		require.Equal(t, tc.want, got, "%q", tc.linkname)
	}
}

// tarfsWriter is the slice of pkg/tarfs the fixtures below drive: the apk
// unpack path, which is the only thing that records a hardlink as one.
type tarfsWriter interface {
	apkfs.FullFS
	WriteHeader(tar.Header, fs.FS, *apk.Package) (bool, error)
}

// writeTarfsFile adds one regular file to m the way apk installs it.
func writeTarfsFile(t *testing.T, m tarfsWriter, name, data string) {
	t.Helper()

	require.NoError(t, m.MkdirAll(filepath.Dir(name), 0o755))
	sum := sha1.Sum([]byte(data)) //nolint:gosec // see the import comment
	_, err := m.WriteHeader(tar.Header{
		Typeflag: tar.TypeReg,
		Name:     name,
		Size:     int64(len(data)),
		Mode:     0o755,
		ModTime:  epoch,
		PAXRecords: map[string]string{
			"APK-TOOLS.checksum.SHA1": hex.EncodeToString(sum[:]),
		},
	}, fstest.MapFS{name: &fstest.MapFile{Data: []byte(data), Mode: 0o755}}, nil)
	require.NoError(t, err, "writing %s", name)
}

// writeTarfsLink adds a TypeLink dirent named name pointing at linkname.
func writeTarfsLink(t *testing.T, m tarfsWriter, name, linkname string) {
	t.Helper()

	require.NoError(t, m.MkdirAll(filepath.Dir(name), 0o755))
	_, err := m.WriteHeader(tar.Header{
		Typeflag: tar.TypeLink,
		Name:     name,
		Linkname: linkname,
		Mode:     0o755,
		ModTime:  epoch,
	}, nil, nil)
	require.NoError(t, err, "linking %s -> %s", name, linkname)
}

func writeImage(t *testing.T, m apkfs.FullFS) string {
	t.Helper()

	out := filepath.Join(t.TempDir(), "image.erofs")
	f, err := os.Create(out)
	require.NoError(t, err)
	require.NoError(t, writeErofs(context.Background(), f, m, t.TempDir(), epoch))
	require.NoError(t, f.Close())
	return out
}

// TestWriteErofs_HardlinkThroughSymlinkedDirIsCopied covers a Linkname that
// reaches its target through a symlinked directory component -- /lib is a
// symlink to /usr/lib in every wolfi image. tarfs follows it at unpack and
// the tar layer path follows it at runtime, but the writer's lookup is a flat
// path map, so it reports ErrNotDirectory rather than ErrNotExist. That has
// to degrade to a copy like any other absent target; before it was counted,
// it aborted the whole build.
func TestWriteErofs_HardlinkThroughSymlinkedDirIsCopied(t *testing.T) {
	const data = "not really a shared object\n"

	m := tarfs.New()
	writeTarfsFile(t, m, "usr/lib/libfoo.so", data)
	require.NoError(t, m.Symlink("usr/lib", "lib"))
	writeTarfsLink(t, m, "usr/bin/libfoo.so", "lib/libfoo.so")

	img := openImage(t, writeImage(t, m))

	content, err := fs.ReadFile(img, "usr/bin/libfoo.so")
	require.NoError(t, err, "the link was neither shared nor materialized")
	require.Equal(t, data, string(content))

	// A copy, not a shared inode: the writer had nothing at "/lib/libfoo.so".
	require.NotEqual(t, statOf(t, img, "usr/lib/libfoo.so").Ino, statOf(t, img, "usr/bin/libfoo.so").Ino)
}

// TestWriteErofs_HardlinkOntoSymlinkSharesTheSymlink pins a deliberate
// divergence from fsys. Writer.Link binds the new name to the entry sitting
// at the target path, so a Linkname landing on a symlink yields a second
// symlink -- dangling here, because the target is relative and the new name
// lives in another directory. tarfs resolves that final component at unpack
// and reports a regular file with content, but link(2) on the tar layer path
// does exactly what the writer does, and matching the tar path is the point.
func TestWriteErofs_HardlinkOntoSymlinkSharesTheSymlink(t *testing.T) {
	m := tarfs.New()
	writeTarfsFile(t, m, "usr/bin/busybox", "busybox\n")
	require.NoError(t, m.Symlink("busybox", "usr/bin/sh"))
	writeTarfsLink(t, m, "opt/mysh", "usr/bin/sh")

	// What the rootfs reports: a second name for a regular file.
	content, err := fs.ReadFile(m, "opt/mysh")
	require.NoError(t, err)
	require.Equal(t, "busybox\n", string(content))

	img := openImage(t, writeImage(t, m))

	lstat, ok := img.(interface {
		Lstat(string) (fs.FileInfo, error)
	})
	require.True(t, ok, "erofs image should expose Lstat")

	info, err := lstat.Lstat("opt/mysh")
	require.NoError(t, err)
	st, ok := info.Sys().(*erofs.Stat)
	require.True(t, ok)
	require.NotZero(t, st.Mode&fs.ModeSymlink, "opt/mysh should be a symlink, not a copy")

	shInfo, err := lstat.Lstat("usr/bin/sh")
	require.NoError(t, err)
	shSt, ok := shInfo.Sys().(*erofs.Stat)
	require.True(t, ok)
	require.Equal(t, shSt.Ino, st.Ino, "the two names should share the symlink inode")
	require.EqualValues(t, 2, st.Nlink)

	// Relative target, resolved from the link name's own directory.
	_, err = fs.ReadFile(img, "opt/mysh")
	require.Error(t, err, "the shared symlink dangles, exactly as link(2) would leave it")
}

// fakeInfo is the smallest fs.FileInfo that can carry a chosen Sys().
type fakeInfo struct {
	fs.FileInfo
	sys any
}

func (f *fakeInfo) Sys() any { return f.sys }
