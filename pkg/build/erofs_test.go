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
	"bytes"
	"context"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	erofs "github.com/erofs/go-erofs"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/apk/apk"
	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/options"
)

// epoch is a fixed timestamp used by reproducibility-sensitive tests so the
// recorded mtime never depends on wall-clock state.
var epoch = time.Unix(1700000000, 0).UTC()

func seedFS(t *testing.T) apkfs.FullFS {
	t.Helper()
	m := apkfs.NewMemFS()
	require.NoError(t, m.MkdirAll("a", 0o755))
	require.NoError(t, m.WriteFile("a/b", []byte("hello world"), 0o644))
	require.NoError(t, m.Symlink("b", "a/link"))
	require.NoError(t, m.SetXattr("a", "user.dir", []byte("foo")))
	require.NoError(t, m.SetXattr("a/b", "user.file", []byte("bar")))
	// stamp known mtimes so the image is reproducible
	require.NoError(t, m.Chtimes("a", epoch, epoch))
	require.NoError(t, m.Chtimes("a/b", epoch, epoch))
	return m
}

func TestWriteErofs_Roundtrip(t *testing.T) {
	m := seedFS(t)

	out := filepath.Join(t.TempDir(), "image.erofs")
	f, err := os.Create(out)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	require.NoError(t, writeErofs(context.Background(), f, m, epoch))
	require.NoError(t, f.Close())

	r, err := os.Open(out)
	require.NoError(t, err)
	defer r.Close()

	img, err := erofs.Open(r)
	require.NoError(t, err)

	// Walk the resulting image and collect what's in it.
	got := map[string]fs.FileInfo{}
	require.NoError(t, fs.WalkDir(img, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		got[path] = info
		return nil
	}))

	require.Contains(t, got, "a", "directory a missing from image")
	require.Contains(t, got, "a/b", "file a/b missing from image")
	require.Contains(t, got, "a/link", "symlink a/link missing from image")

	// File content
	data, err := fs.ReadFile(img, "a/b")
	require.NoError(t, err)
	require.Equal(t, "hello world", string(data))

	// Xattrs (via the accessor interface advertised by erofs.Stat)
	dirX, ok := got["a"].Sys().(*erofs.Stat)
	require.True(t, ok, "expected *erofs.Stat on dir Sys()")
	require.Equal(t, "foo", dirX.Xattrs["user.dir"])

	fileX := got["a/b"].Sys().(*erofs.Stat)
	require.Equal(t, "bar", fileX.Xattrs["user.file"])

	// Symlink target — readable via the image's ReadLink method.
	rl, ok := img.(interface {
		ReadLink(string) (string, error)
	})
	require.True(t, ok, "image does not implement ReadLink")
	target, err := rl.ReadLink("a/link")
	require.NoError(t, err)
	require.Equal(t, "b", target)
}

// TestImageLayoutToLayer_Erofs exercises ImageLayoutToLayer end-to-end via a
// hand-rolled Context. It confirms the layer returned advertises the erofs
// media type and that DiffID == Digest (raw EROFS has no compression step).
func TestImageLayoutToLayer_Erofs(t *testing.T) {
	m := seedFS(t)
	// checkPaths warns about missing /etc/passwd, /etc/group, /etc/os-release;
	// satisfy those so we get clean test logs.
	require.NoError(t, m.MkdirAll("etc", 0o755))
	require.NoError(t, m.WriteFile("etc/passwd", []byte("root:x:0:0:root:/root:/bin/sh\n"), 0o644))
	require.NoError(t, m.WriteFile("etc/group", []byte("root:x:0:root\n"), 0o644))
	require.NoError(t, m.WriteFile("etc/os-release", []byte("ID=test\n"), 0o644))

	tmp := t.TempDir()
	bc := &Context{
		ic: types.ImageConfiguration{Format: types.LayerFormatErofs},
		o: options.Options{
			TempDirPath:     tmp,
			SourceDateEpoch: epoch,
		},
		fs: m,
	}

	path, layer, err := bc.ImageLayoutToLayer(context.Background())
	require.NoError(t, err)

	mt, err := layer.MediaType()
	require.NoError(t, err)
	require.Equal(t, v1types.MediaType("application/vnd.erofs"), mt)

	digest, err := layer.Digest()
	require.NoError(t, err)
	diffID, err := layer.DiffID()
	require.NoError(t, err)
	require.Equal(t, digest, diffID, "raw EROFS: Digest must equal DiffID")

	// Confirm the on-disk artifact really is an EROFS image.
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	_, err = erofs.Open(f)
	require.NoError(t, err)
}

// TestWriteErofs_FsckErofs validates a generated image with the C reference
// tool from erofs-utils. The test is skipped when fsck.erofs is not on PATH so
// contributors without erofs-utils installed still get a green build. CI
// images that include erofs-utils will actually exercise this path.
func TestWriteErofs_FsckErofs(t *testing.T) {
	fsckBin, err := exec.LookPath("fsck.erofs")
	if err != nil {
		t.Skip("fsck.erofs not found in PATH; install erofs-utils to run this test")
	}

	m := seedFS(t)
	out := filepath.Join(t.TempDir(), "image.erofs")
	f, err := os.Create(out)
	require.NoError(t, err)
	require.NoError(t, writeErofs(context.Background(), f, m, epoch))
	require.NoError(t, f.Close())

	// Plain integrity check: superblock CRC, layout, all reachable inodes.
	cmd := exec.Command(fsckBin, "-d3", out)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "fsck.erofs reported a malformed image:\n%s", output)

	// Full content extraction with xattr verification. This walks every
	// inode, decompresses any data, and writes files to disk — a stronger
	// signal than the integrity check alone.
	extractDir := t.TempDir()
	cmd = exec.Command(fsckBin, "--extract="+extractDir, "--xattrs", "--force", out)
	output, err = cmd.CombinedOutput()
	require.NoError(t, err, "fsck.erofs --extract failed:\n%s", output)

	// Sanity-check the extracted content actually matches what we put in.
	data, err := os.ReadFile(filepath.Join(extractDir, "a", "b"))
	require.NoError(t, err)
	require.Equal(t, "hello world", string(data))

	target, err := os.Readlink(filepath.Join(extractDir, "a", "link"))
	require.NoError(t, err)
	require.Equal(t, "b", target)
}

func TestSplitErofsLayers(t *testing.T) {
	fsys := apkfs.NewMemFS()
	require.NoError(t, fsys.MkdirAll("usr/lib/apk/db", 0o755))
	require.NoError(t, fsys.WriteFile("usr/lib/apk/db/installed", []byte("idb top\n"), 0o644))
	require.NoError(t, fsys.MkdirAll("etc", 0o755))
	require.NoError(t, fsys.WriteFile("etc/hello", []byte("hi\n"), 0o644))

	pkg1 := newPkg("pkg1")
	pkg2 := newPkg("pkg2")
	groups := []*group{
		{pkgs: []*apk.Package{pkg1}, size: 1000, tiebreaker: "pkg1"},
		{pkgs: []*apk.Package{pkg2}, size: 2000, tiebreaker: "pkg2"},
	}
	pkgToDiff := map[*apk.Package][]byte{
		pkg1: []byte("pkg1 info\n"),
		pkg2: []byte("pkg2 info\n"),
	}

	layers, err := splitErofsLayers(context.Background(), fsys, groups, pkgToDiff, t.TempDir(), epoch)
	require.NoError(t, err)
	require.Len(t, layers, 3, "expected 2 group layers + 1 top layer")

	// All three layers should be valid EROFS images.
	fsckBin, _ := lookFsckErofs()
	for i, l := range layers {
		erl, ok := l.(*erofsLayer)
		require.True(t, ok, "layer[%d] not *erofsLayer", i)

		mt, err := l.MediaType()
		require.NoError(t, err)
		require.Equal(t, "application/vnd.erofs", string(mt))

		// Layer roles: overlay-lower on the package layers, absent on the top.
		anns := erl.LayerAnnotations()
		if i < len(layers)-1 {
			require.Equal(t, "overlay-lower", anns[erofsRoleAnnotation], "layer[%d] missing overlay-lower role", i)
		} else {
			require.Empty(t, anns, "top layer must carry no role annotation")
		}

		// The image must parse via go-erofs.
		f, err := os.Open(erl.path)
		require.NoError(t, err)
		_, err = erofs.Open(f)
		_ = f.Close()
		require.NoError(t, err, "layer[%d] is not a valid EROFS image", i)

		if fsckBin != "" {
			cmd := exec.Command(fsckBin, "-d3", erl.path)
			out, err := cmd.CombinedOutput()
			require.NoError(t, err, "fsck.erofs rejected layer[%d]:\n%s", i, out)
		}
	}

	// The package layers must each carry their own partial installed db; the
	// top layer carries the source file via the normal path.
	for i, l := range layers[:2] {
		erl := l.(*erofsLayer)
		f, err := os.Open(erl.path)
		require.NoError(t, err)
		img, err := erofs.Open(f)
		require.NoError(t, err)
		data, err := fs.ReadFile(img, "usr/lib/apk/db/installed")
		require.NoError(t, err, "layer[%d] missing per-group installed db", i)
		require.NotEmpty(t, data, "layer[%d] installed db must not be empty", i)
		_ = f.Close()
	}

	// The top layer should hold etc/hello (unowned content) and the original
	// installed db.
	topL := layers[len(layers)-1].(*erofsLayer)
	tf, err := os.Open(topL.path)
	require.NoError(t, err)
	defer tf.Close()
	topImg, err := erofs.Open(tf)
	require.NoError(t, err)
	hello, err := fs.ReadFile(topImg, "etc/hello")
	require.NoError(t, err)
	require.Equal(t, "hi\n", string(hello))
	topIdb, err := fs.ReadFile(topImg, "usr/lib/apk/db/installed")
	require.NoError(t, err)
	require.Equal(t, "idb top\n", string(topIdb))
}

func newPkg(name string) *apk.Package {
	return &apk.Package{Name: name, Origin: name, Version: "1.0.0", InstalledSize: 1024}
}

func lookFsckErofs() (string, error) {
	return exec.LookPath("fsck.erofs")
}

func TestWriteErofs_Reproducible(t *testing.T) {
	build := func(path string) []byte {
		m := seedFS(t)
		f, err := os.Create(path)
		require.NoError(t, err)
		require.NoError(t, writeErofs(context.Background(), f, m, epoch))
		require.NoError(t, f.Close())
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		return data
	}

	tmp := t.TempDir()
	a := build(filepath.Join(tmp, "a.erofs"))
	b := build(filepath.Join(tmp, "b.erofs"))
	require.Equal(t, len(a), len(b), "image sizes differ between identical builds")
	require.True(t, bytes.Equal(a, b), "two identical builds produced byte-different images")
}
