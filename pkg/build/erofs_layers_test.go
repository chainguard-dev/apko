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
	"path"
	"sort"
	"testing"
	"testing/fstest"
	"time"

	erofs "github.com/erofs/go-erofs"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/apk/apk"
	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/tarfs"
)

// entry describes one node in a tarfs fixture. A nil pkg means the entry is
// not owned by any package, which is what apko's own post-install steps
// produce.
type entry struct {
	path string
	data string
	pkg  *apk.Package
	dir  bool
}

func dirEntry(p string) entry { return entry{path: p, dir: true} }

func newPkg(name string) *apk.Package {
	return &apk.Package{Name: name, Origin: name, Version: "1.0.0", InstalledSize: 1024}
}

// tarfsFixture builds a pkg/tarfs filesystem, which is what a real apko build
// walks. apkfs.NewMemFS() cannot stand in for it here: its FileInfo has no
// Package() method at all, so every file in a MemFS fixture is unowned by
// construction and package routing is never exercised.
func tarfsFixture(t *testing.T, entries []entry) apkfs.FullFS {
	t.Helper()

	// tarfs keeps regular file data in the fs.FS the header came from and
	// reads it back lazily, so the fixture needs one to point at.
	content := fstest.MapFS{}
	for _, e := range entries {
		if !e.dir {
			content[e.path] = &fstest.MapFile{Data: []byte(e.data), Mode: 0o644}
		}
	}

	m := tarfs.New()
	for _, e := range entries {
		if e.dir {
			require.NoError(t, m.MkdirAll(e.path, 0o755))
			require.NoError(t, m.Chtimes(e.path, epoch, epoch))
			continue
		}
		require.NoError(t, m.MkdirAll(path.Dir(e.path), 0o755))

		sum := sha1.Sum([]byte(e.data)) //nolint:gosec // see the import comment
		hdr := tar.Header{
			Typeflag: tar.TypeReg,
			Name:     e.path,
			Size:     int64(len(e.data)),
			Mode:     0o644,
			ModTime:  epoch,
			PAXRecords: map[string]string{
				"APK-TOOLS.checksum.SHA1": hex.EncodeToString(sum[:]),
			},
		}
		_, err := m.WriteHeader(hdr, content, e.pkg)
		require.NoError(t, err, "writing %s", e.path)
	}
	return m
}

// layerPaths returns the sorted set of paths an EROFS layer contains,
// excluding the root.
func layerPaths(t *testing.T, l v1.Layer) []string {
	t.Helper()

	erl, ok := l.(*erofsLayer)
	require.True(t, ok, "layer is not an *erofsLayer")

	f, err := os.Open(erl.path)
	require.NoError(t, err)
	defer f.Close()

	img, err := erofs.Open(f)
	require.NoError(t, err)

	var out []string
	require.NoError(t, fs.WalkDir(img, ".", func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p != "." {
			out = append(out, p)
		}
		return nil
	}))
	sort.Strings(out)
	return out
}

func TestSplitErofsLayers_RoutesFilesToTheirPackageLayer(t *testing.T) {
	pkg1, pkg2 := newPkg("pkg1"), newPkg("pkg2")
	fsys := tarfsFixture(t, []entry{
		dirEntry("usr/lib/apk/db"),
		{path: "usr/lib/apk/db/installed", data: "pkg1 info\npkg2 info\n"},
		{path: "usr/bin/one", data: "one\n", pkg: pkg1},
		{path: "usr/share/one/data", data: "data\n", pkg: pkg1},
		{path: "usr/bin/two", data: "two\n", pkg: pkg2},
		{path: "etc/hello", data: "hi\n"},
	})

	// Groups are ordered the way groupByOriginAndSize hands them over: one
	// group per origin, largest first, with the top layer appended last.
	groups := []*group{
		{pkgs: []*apk.Package{pkg1}, size: 2000, tiebreaker: "pkg1"},
		{pkgs: []*apk.Package{pkg2}, size: 1000, tiebreaker: "pkg2"},
	}
	pkgToDiff := map[*apk.Package][]byte{
		pkg1: []byte("pkg1 info\n"),
		pkg2: []byte("pkg2 info\n"),
	}

	layers, err := splitErofsLayers(context.Background(), fsys, groups, pkgToDiff, t.TempDir(), epoch)
	require.NoError(t, err)
	require.Len(t, layers, 3)

	one, two, top := layerPaths(t, layers[0]), layerPaths(t, layers[1]), layerPaths(t, layers[2])

	// Each package's files land in its own group layer and nowhere else.
	require.Contains(t, one, "usr/bin/one")
	require.Contains(t, one, "usr/share/one/data")
	require.NotContains(t, one, "usr/bin/two")
	require.NotContains(t, one, "etc/hello")

	require.Contains(t, two, "usr/bin/two")
	require.NotContains(t, two, "usr/bin/one")

	require.NotContains(t, top, "usr/bin/one")
	require.NotContains(t, top, "usr/bin/two")
	require.Contains(t, top, "etc/hello")

	// Ancestors of a routed file are recreated in the layer that needs them,
	// so each group layer is mountable on its own.
	require.Contains(t, one, "usr")
	require.Contains(t, one, "usr/bin")
	require.Contains(t, two, "usr/bin")

	// Every group layer carries a partial installed db naming only its own
	// packages; the top layer carries the real one.
	require.Equal(t, "pkg1 info\n", string(readLayerFile(t, layers[0], "usr/lib/apk/db/installed")))
	require.Equal(t, "pkg2 info\n", string(readLayerFile(t, layers[1], "usr/lib/apk/db/installed")))
	require.Equal(t, "pkg1 info\npkg2 info\n", string(readLayerFile(t, layers[2], "usr/lib/apk/db/installed")))
}

func TestSplitErofsLayers_EmitsDirOnlySubtrees(t *testing.T) {
	pkg1 := newPkg("pkg1")
	fsys := tarfsFixture(t, []entry{
		dirEntry("usr/lib/apk/db"),
		{path: "usr/lib/apk/db/installed", data: "pkg1 info\n"},
		{path: "usr/bin/one", data: "one\n", pkg: pkg1},
		// Directories with no file anywhere beneath them. apko creates these
		// from `paths:` and from the base layout, and an image without them
		// has no /tmp to write to and no mount points to mount over.
		dirEntry("tmp"),
		dirEntry("run"),
		dirEntry("var/empty"),
	})

	groups := []*group{{pkgs: []*apk.Package{pkg1}, size: 1000, tiebreaker: "pkg1"}}
	pkgToDiff := map[*apk.Package][]byte{pkg1: []byte("pkg1 info\n")}

	layers, err := splitErofsLayers(context.Background(), fsys, groups, pkgToDiff, t.TempDir(), epoch)
	require.NoError(t, err)
	require.Len(t, layers, 2)

	// They belong to no package, so they land in the top layer.
	top := layerPaths(t, layers[len(layers)-1])
	for _, want := range []string{"tmp", "run", "var", "var/empty"} {
		require.Contains(t, top, want, "dir-only subtree missing from every layer")
	}
}

func TestSplitErofsLayers_LayersAreValidImages(t *testing.T) {
	pkg1, pkg2 := newPkg("pkg1"), newPkg("pkg2")
	fsys := tarfsFixture(t, []entry{
		dirEntry("usr/lib/apk/db"),
		{path: "usr/lib/apk/db/installed", data: "pkg1 info\npkg2 info\n"},
		{path: "usr/bin/one", data: "one\n", pkg: pkg1},
		{path: "usr/bin/two", data: "two\n", pkg: pkg2},
		{path: "etc/hello", data: "hi\n"},
	})

	groups := []*group{
		{pkgs: []*apk.Package{pkg1}, size: 2000, tiebreaker: "pkg1"},
		{pkgs: []*apk.Package{pkg2}, size: 1000, tiebreaker: "pkg2"},
	}
	pkgToDiff := map[*apk.Package][]byte{
		pkg1: []byte("pkg1 info\n"),
		pkg2: []byte("pkg2 info\n"),
	}

	layers, err := splitErofsLayers(context.Background(), fsys, groups, pkgToDiff, t.TempDir(), epoch)
	require.NoError(t, err)
	require.Len(t, layers, 3)

	fsckBin := optionalFsckErofs(t)
	for i, l := range layers {
		erl, ok := l.(*erofsLayer)
		require.True(t, ok, "layer[%d] is not an *erofsLayer", i)

		mt, err := l.MediaType()
		require.NoError(t, err)
		require.Equal(t, types.ErofsLayerMediaType, string(mt))

		// Every layer but the final one carries role=overlay-lower, per spec
		// §3.8 rule 1.
		anns := erl.LayerAnnotations()
		if i < len(layers)-1 {
			require.Equal(t, types.ErofsRoleOverlayLower, anns[types.ErofsRoleAnnotation], "layer[%d]", i)
		} else {
			require.Empty(t, anns, "the final layer must carry no role annotation")
		}

		f, err := os.Open(erl.path)
		require.NoError(t, err)
		_, err = erofs.Open(f)
		_ = f.Close()
		require.NoError(t, err, "layer[%d] is not a valid EROFS image", i)

		if fsckBin != "" {
			out, err := exec.Command(fsckBin, "-d3", erl.path).CombinedOutput()
			require.NoError(t, err, "fsck.erofs rejected layer[%d]:\n%s", i, out)
		}
	}
}

// TestSplitErofsLayers_ZeroBuildTimeIsEpoch is the layered counterpart of
// TestWriteErofs_ZeroBuildTimeIsEpoch: a caller that leaves the build time
// zero must still get the same layers twice, not a wall-clock stamp.
func TestSplitErofsLayers_ZeroBuildTimeIsEpoch(t *testing.T) {
	pkg1 := newPkg("pkg1")

	split := func(buildTime time.Time) []v1.Hash {
		fsys := tarfsFixture(t, []entry{
			dirEntry("usr/lib/apk/db"),
			{path: "usr/lib/apk/db/installed", data: "pkg1 info\n"},
			{path: "usr/bin/one", data: "one\n", pkg: pkg1},
			{path: "etc/hello", data: "hi\n"},
		})
		groups := []*group{{pkgs: []*apk.Package{pkg1}, size: 1000, tiebreaker: "pkg1"}}
		pkgToDiff := map[*apk.Package][]byte{pkg1: []byte("pkg1 info\n")}

		layers, err := splitErofsLayers(context.Background(), fsys, groups, pkgToDiff, t.TempDir(), buildTime)
		require.NoError(t, err)

		out := make([]v1.Hash, 0, len(layers))
		for _, l := range layers {
			d, err := l.Digest()
			require.NoError(t, err)
			out = append(out, d)
		}
		return out
	}

	require.Equal(t, split(time.Unix(0, 0)), split(time.Time{}),
		"a zero buildTime must produce the same layers as an explicit epoch")
}

func TestSplitErofsLayers_UngroupedPackageIsAnError(t *testing.T) {
	pkg1, orphan := newPkg("pkg1"), newPkg("orphan")
	fsys := tarfsFixture(t, []entry{
		{path: "usr/bin/one", data: "one\n", pkg: pkg1},
		{path: "usr/bin/orphan", data: "orphan\n", pkg: orphan},
	})

	groups := []*group{{pkgs: []*apk.Package{pkg1}, size: 1000, tiebreaker: "pkg1"}}
	pkgToDiff := map[*apk.Package][]byte{pkg1: []byte("pkg1 info\n")}

	tmpdir := t.TempDir()
	_, err := splitErofsLayers(context.Background(), fsys, groups, pkgToDiff, tmpdir, epoch)
	require.ErrorContains(t, err, "orphan")

	// And nothing is left behind on the way out.
	require.Empty(t, lsDir(t, tmpdir), "temp layer files leaked on the error path")
}

// TestSplitErofsLayers_CleansUpOnError covers the other shape of failure: an
// error raised part-way through the walk rather than before it starts.
func TestSplitErofsLayers_CleansUpOnError(t *testing.T) {
	pkg1 := newPkg("pkg1")
	fsys := tarfsFixture(t, []entry{
		{path: "usr/bin/one", data: "one\n", pkg: pkg1},
		{path: "etc/hello", data: "hi\n"},
	})

	groups := []*group{{pkgs: []*apk.Package{pkg1}, size: 1000, tiebreaker: "pkg1"}}
	pkgToDiff := map[*apk.Package][]byte{pkg1: []byte("pkg1 info\n")}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	tmpdir := t.TempDir()
	_, err := splitErofsLayers(ctx, fsys, groups, pkgToDiff, tmpdir, epoch)
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, lsDir(t, tmpdir), "temp layer files leaked on the error path")
}

func lsDir(t *testing.T, dir string) []string {
	t.Helper()

	ents, err := os.ReadDir(dir)
	require.NoError(t, err)

	out := make([]string, 0, len(ents))
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

func readLayerFile(t *testing.T, l v1.Layer, name string) []byte {
	t.Helper()

	erl, ok := l.(*erofsLayer)
	require.True(t, ok, "layer is not an *erofsLayer")

	f, err := os.Open(erl.path)
	require.NoError(t, err)
	defer f.Close()

	img, err := erofs.Open(f)
	require.NoError(t, err)

	data, err := fs.ReadFile(img, name)
	require.NoError(t, err, "reading %s", name)
	return data
}
