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

package build_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha1" //nolint:gosec // APK per-file checksums are SHA-1
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/go-cmp/cmp"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/apk/apk"
	apktypes "chainguard.dev/apko/pkg/apk/types"
	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/tarfs"
)

// fakePackage holds package metadata, tar headers, and file data.
type fakePackage struct {
	info    *apktypes.PackageInfo
	entries []tar.Header
	files   fstest.MapFS
	report  func(name string, data []byte) string
}

func (p fakePackage) PkgInfo() (*apktypes.PackageInfo, error) { return p.info, nil }
func (p fakePackage) ControlSection() ([]byte, error)         { return []byte("control " + p.info.Name), nil }
func (p fakePackage) ControlData() ([]byte, error)            { return nil, nil }
func (p fakePackage) Size() int64                             { return int64(p.info.Size) }
func (p fakePackage) Entries() ([]tar.Header, error)          { return p.entries, nil }
func (p fakePackage) FS() fs.FS                               { return digestingFS{p.files, p.report} }

// digestingFS implements apk.ContentDigester for package contents.
// It uses report to return digests without reading files.
type digestingFS struct {
	fstest.MapFS
	report func(name string, data []byte) string
}

func (d digestingFS) ContentDigest(name string) (string, bool) {
	f, ok := d.MapFS[name]
	if !ok {
		return "", false
	}
	return d.report(name, f.Data), true
}

// sha256Of returns a digest in the format used when planning hashes content.
func sha256Of(b []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(b)) }

func reportSHA256(_ string, data []byte) string { return sha256Of(data) }

// apkEntry is one archive entry of a fake APK; data is a regular file's content.
type apkEntry struct {
	tar.Header
	data string
}

func apkChecksum(b string) map[string]string {
	sum := sha1.Sum([]byte(b)) //nolint:gosec
	return map[string]string{"APK-TOOLS.checksum.SHA1": hex.EncodeToString(sum[:])}
}

func file(name, data string) apkEntry {
	return apkEntry{tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0o644, Size: int64(len(data)), PAXRecords: apkChecksum(data)}, data}
}

func dir(name string) apkEntry {
	return apkEntry{Typeflag: tar.TypeDir, Name: name, Mode: 0o755}
}

func symlink(name, target string) apkEntry {
	return apkEntry{Typeflag: tar.TypeSymlink, Name: name, Linkname: target, PAXRecords: apkChecksum(target)}
}

func hardlink(name, target string) apkEntry {
	return apkEntry{Typeflag: tar.TypeLink, Name: name, Linkname: target}
}

func (e apkEntry) at(sec int64) apkEntry {
	e.ModTime = time.Unix(sec, 0).UTC()
	return e
}

func (e apkEntry) pax(k, v string) apkEntry {
	e.PAXRecords = maps.Clone(e.PAXRecords)
	e.PAXRecords[k] = v
	return e
}

// newPackage returns a package with the entries in archive order.
func newPackage(name, origin string, size uint64, entries ...apkEntry) fakePackage {
	p := fakePackage{
		info:   &apktypes.PackageInfo{Name: name, Origin: origin, Version: "1", Size: size},
		files:  fstest.MapFS{},
		report: reportSHA256,
	}
	for _, e := range entries {
		if e.Typeflag == tar.TypeReg {
			p.files[e.Name] = &fstest.MapFile{Data: []byte(e.data), Mode: 0o644}
		}
		p.entries = append(p.entries, e.Header)
	}
	return p
}

// fakePackages returns three packages from two origins with xattrs, a
// symlink, a hard link, an empty file, and etc/passwd for the build to
// rewrite.
func fakePackages(report func(name string, data []byte) string) []apk.PackageContents {
	pkgs := []fakePackage{
		newPackage("a", "a", 3000,
			dir("etc").at(10), dir("usr").at(11), dir("usr/bin").at(12), dir("usr/share").at(14), dir("usr/share/a").at(15),
			file("usr/bin/a", "a binary\n").at(100).pax("SCHILY.xattr.security.capability", "\x01\x00\x00\x02"),
			file("etc/a.conf", "a=1\n").at(120),
			file("etc/passwd", "root:x:0:0:root:/root:/bin/sh\n").at(125),
			file("usr/share/a/empty", "").at(130),
			symlink("usr/bin/a-link", "a").at(101).pax("APK-TOOLS.checksum.SHA1", hex.EncodeToString(make([]byte, 20))),
			hardlink("usr/bin/a-alias", "usr/bin/a").at(100),
		),
		newPackage("b", "b", 2000,
			dir("usr").at(21), dir("usr/bin").at(22), dir("usr/share").at(23), dir("usr/share/b").at(24),
			file("usr/bin/b", "b binary, a bit longer than a's\n").at(200),
			file("usr/share/b/data", "b data").at(210),
		),
		newPackage("b-dev", "b", 100, dir("usr").at(31), dir("usr/include").at(32), file("usr/include/b.h", "#define B 1\n").at(300)),
	}
	out := make([]apk.PackageContents, 0, len(pkgs))
	for _, p := range pkgs {
		p.report = report
		out = append(out, p)
	}
	return out
}

// unusedRepository names a repository that builds with pre-resolved
// packages do not read.
const unusedRepository = "/nonexistent/layer-plans"

// newBuild configures a build of ic on a fresh filesystem with isolated
// directories, a fixed architecture, and a fixed source date epoch.
func newBuild(t *testing.T, ic types.ImageConfiguration, opts ...build.Option) *build.Context {
	t.Helper()
	bc, err := build.New(t.Context(), tarfs.New(), withIsolatedDirs(t, append([]build.Option{
		build.WithImageConfiguration(ic),
		build.WithArch(types.ParseArchitecture("x86_64")),
		build.WithSourceDateEpoch(time.Unix(1700000000, 0).UTC()),
	}, opts...)...)...)
	require.NoError(t, err)
	return bc
}

// orderedContext configures a layered build of pkgs, with the APK layer
// order and no accounts.
func orderedContext(t *testing.T, pkgs []apk.PackageContents, paths ...types.PathMutation) *build.Context {
	t.Helper()
	return newBuild(t, types.ImageConfiguration{
		Contents: types.ImageContents{Repositories: []string{unusedRepository}},
		Paths:    paths,
		Layering: &types.Layering{Strategy: "origin", Budget: 2},
	}, build.WithPreResolvedPackages(pkgs), build.WithAPKLayerOrder(true))
}

// buildAndPlan builds and plans pkgs in the APK layer order, checks the
// plans' order and that rendering them matches the built layers' digests,
// and returns the plans.
func buildAndPlan(t *testing.T, pkgs []apk.PackageContents, paths ...types.PathMutation) []*build.LayerPlan {
	t.Helper()
	layers, err := orderedContext(t, pkgs, paths...).BuildLayers(t.Context())
	require.NoError(t, err)
	plans, content := planLayers(t, orderedContext(t, pkgs, paths...))
	require.Len(t, plans, len(layers))
	checkLayerOrder(t, plans)
	for i, layer := range layers {
		want, err := layer.Digest()
		require.NoError(t, err)
		_, got := render(t, plans[i], content)
		require.Equal(t, want, got.Digest, "layer %d", i)
	}
	return plans
}

// nonrootChownConfig configures a layered build that adds a user, which
// rewrites etc/passwd, and changes the ownership of usr/share/b/data.
func nonrootChownConfig() types.ImageConfiguration {
	uid, gid := uint32(65532), uint32(65532)
	return types.ImageConfiguration{
		Contents: types.ImageContents{Repositories: []string{unusedRepository}},
		Accounts: types.ImageAccounts{
			Users:  []types.User{{UserName: "nonroot", UID: uid, GID: &gid, HomeDir: "/home/nonroot"}},
			Groups: []types.Group{{GroupName: "nonroot", GID: gid}},
		},
		Paths:    []types.PathMutation{{Path: "usr/share/b/data", Type: "permissions", UID: &uid, GID: &gid, Permissions: 0o644}},
		Layering: &types.Layering{Strategy: "origin", Budget: 2},
	}
}

// newContext configures a nonrootChownConfig build of fakePackages.
func newContext(t *testing.T, report func(name string, data []byte) string, opts ...build.Option) *build.Context {
	t.Helper()
	return newBuild(t, nonrootChownConfig(), append([]build.Option{build.WithPreResolvedPackages(fakePackages(report))}, opts...)...)
}

func planLayers(t *testing.T, bc *build.Context) ([]*build.LayerPlan, *build.LayerContent) {
	t.Helper()
	plans, content, err := bc.PlanLayers(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return plans, content
}

func render(t *testing.T, p *build.LayerPlan, content *build.LayerContent) ([]byte, *build.LayerDigests) {
	t.Helper()
	var buf bytes.Buffer
	d, err := p.Render(t.Context(), content, &buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), d
}

// TestRenderMatchesBuildLayers checks that Render matches BuildLayers'
// compressed bytes and digests with both gzip and plain tar storage.
func TestRenderMatchesBuildLayers(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		t.Run(fmt.Sprintf("compressed=%v", compressed), func(t *testing.T) {
			want, err := newContext(t, reportSHA256, build.WithCompressedLayerFile(compressed)).BuildLayers(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			plans, content := planLayers(t, newContext(t, reportSHA256))
			if len(plans) != len(want) {
				t.Fatalf("planned %d layers, BuildLayers wrote %d", len(plans), len(want))
			}
			for i := range want {
				rc, err := want[i].Compressed()
				if err != nil {
					t.Fatal(err)
				}
				wantBytes, err := io.ReadAll(rc)
				rc.Close()
				if err != nil {
					t.Fatal(err)
				}
				wantDiffID, err := want[i].DiffID()
				if err != nil {
					t.Fatal(err)
				}
				wantDigest, err := want[i].Digest()
				if err != nil {
					t.Fatal(err)
				}

				got, d := render(t, plans[i], content)
				if d.DiffID != wantDiffID {
					t.Errorf("layer %d: Render diffid = %s, want %s", i, d.DiffID, wantDiffID)
				}
				if d.Digest != wantDigest || d.Size != int64(len(wantBytes)) || !bytes.Equal(got, wantBytes) {
					t.Errorf("layer %d: Render digest = %s (%d bytes), want %s (%d bytes)", i, d.Digest, d.Size, wantDigest, len(wantBytes))
				}
			}
		})
	}
}

// TestAPKLayerOrder checks that the APK layer order writes the same entries
// as the default order, with the build's rewritten passwd, chown and chmod,
// xattrs, mtimes, and hard links, and that Render matches BuildLayers.
func TestAPKLayerOrder(t *testing.T) {
	ctx := t.Context()
	// b and b-dev share bytes, so one layer has identical content in two packages.
	const bData = "b data"
	withPkgs := build.WithPreResolvedPackages([]apk.PackageContents{
		newPackage("a", "a", 3000,
			dir("etc").at(10), dir("usr").at(11), dir("usr/bin").at(12),
			file("usr/bin/a", "a binary\n").at(100).pax("SCHILY.xattr.security.capability", "\x01\x00\x00\x02"),
			file("etc/a.conf", "a=1\n").at(120),
			file("etc/passwd", "root:x:0:0:root:/root:/bin/sh\n").at(125),
			hardlink("usr/bin/a-alias", "usr/bin/a").at(100),
			file("usr/bin/empty", ""),
			symlink("usr/bin/a-link", "a"),
		),
		newPackage("b", "b", 2000,
			dir("usr").at(21), dir("usr/bin").at(22), dir("usr/share").at(23), dir("usr/share/b").at(24),
			file("usr/bin/b", "b binary\n").at(200),
			file("usr/share/b/data", bData).at(210),
		),
		newPackage("b-dev", "b", 100,
			dir("usr").at(31), dir("usr/include").at(32),
			file("usr/include/b.h", "#define B 1\n").at(300),
			file("usr/include/c-data", bData).at(210),
		),
	})
	normal, err := newBuild(t, nonrootChownConfig(), withPkgs).BuildLayers(ctx)
	require.NoError(t, err)
	reordered, err := newBuild(t, nonrootChownConfig(), withPkgs, build.WithAPKLayerOrder(true)).BuildLayers(ctx)
	require.NoError(t, err)
	plans, content := planLayers(t, newBuild(t, nonrootChownConfig(), withPkgs, build.WithAPKLayerOrder(true)))
	checkLayerOrder(t, plans)
	// The build rewrites etc/passwd and keeps usr/bin/a-alias as a hard link.
	checkLayerPaths(t, plans, "a", "etc/passwd", "usr/bin/a", "etc/a.conf", "usr/bin/a-alias")
	checkLayerPaths(t, plans, "b", "usr/bin/b", "usr/share/b/data", "usr/include/b.h", "usr/include/c-data")
	require.Len(t, reordered, len(normal))
	require.Len(t, plans, len(normal))

	read := func(layer v1.Layer) []writtenEntry {
		rc, err := layer.Compressed()
		require.NoError(t, err)
		defer rc.Close()
		data, err := io.ReadAll(rc)
		require.NoError(t, err)
		return readLayer(t, data)
	}
	for i, layer := range reordered {
		before, after := read(normal[i]), read(layer)
		require.ElementsMatch(t, before, after, "entries of layer %d", i)
		_, digests := render(t, plans[i], content)
		builtDigest, err := layer.Digest()
		require.NoError(t, err)
		require.Equal(t, builtDigest, digests.Digest, "layer %d", i)
	}
}

// checkLayerPaths checks that the layer with the named package's files lists
// the given paths in that order, each once, and returns their positions among
// the layer's entries.
func checkLayerPaths(t *testing.T, plans []*build.LayerPlan, pkg string, want ...string) map[string]int {
	t.Helper()
	for _, p := range plans {
		if !slices.ContainsFunc(p.Packages(), func(q *apk.Package) bool { return q.Name == pkg }) {
			continue
		}
		var got []string
		at := map[string]int{}
		for i, e := range p.Entries() {
			if slices.Contains(want, e.Header.Name) {
				got = append(got, e.Header.Name)
				at[e.Header.Name] = i
			}
		}
		require.Equal(t, want, got, "paths in the layer with package %s", pkg)
		return at
	}
	require.FailNow(t, "no layer has package "+pkg)
	return nil
}

// checkLayerOrder checks that no entry of the plans' layers has a symlink
// among its parent directories, so extracting the layers never writes through
// a symlink, and that each entry comes after its parent directory and, for a
// hard link, after its target, when those are in the same layer.
func checkLayerOrder(t *testing.T, plans []*build.LayerPlan) {
	t.Helper()
	symlinks := map[string]bool{}
	for _, p := range plans {
		for _, e := range p.Entries() {
			if e.Header.Typeflag == tar.TypeSymlink {
				symlinks[path.Clean(e.Header.Name)] = true
			}
		}
	}
	for _, p := range plans {
		index := map[string]int{}
		for i, e := range p.Entries() {
			index[path.Clean(e.Header.Name)] = i
		}
		for i, e := range p.Entries() {
			name := path.Clean(e.Header.Name)
			for dir := path.Dir(name); dir != "."; dir = path.Dir(dir) {
				require.False(t, symlinks[dir], "%s is under the symlink %s", name, dir)
			}
			if j, ok := index[path.Dir(name)]; ok {
				require.Less(t, j, i, "%s precedes its parent directory", name)
			}
			if e.Header.Typeflag == tar.TypeLink {
				if j, ok := index[path.Clean(e.Header.Linkname)]; ok {
					require.Less(t, j, i, "hard link %s precedes its target", name)
				}
			}
		}
	}
}

// A name repeated in an APK with the same content is ordered by its first
// occurrence, which is the one the build filesystem keeps.
func TestAPKLayerOrderRepeatedName(t *testing.T) {
	plans := buildAndPlan(t, []apk.PackageContents{newPackage("a", "a", 100,
		dir("etc"),
		file("etc/z", "z\n"),
		file("etc/a", "a\n"),
		file("etc/z", "z\n"),
	)})
	checkLayerPaths(t, plans, "a", "etc/z", "etc/a")
}

type writtenEntry struct {
	Header  tar.Header
	Content string
}

// readLayer reads every entry of a gzipped layer.
func readLayer(t *testing.T, b []byte) []writtenEntry {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	var out []writtenEntry
	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		c, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, writtenEntry{Header: *hdr, Content: string(c)})
	}
}

func hasContent(hdr *tar.Header) bool { return hdr.Typeflag == tar.TypeReg && hdr.Size > 0 }

// TestLayerPlanEntries checks header order, header values, and content
// digests against the rendered layer. Only non-empty regular files have
// digests.
func TestLayerPlanEntries(t *testing.T) {
	plans, content := planLayers(t, newContext(t, reportSHA256))
	for i, p := range plans {
		b, _ := render(t, p, content)
		written := readLayer(t, b)

		// Round trip the planned headers through archive/tar to compare
		// them with the rendered headers.
		var tw bytes.Buffer
		w := tar.NewWriter(&tw)
		entries := p.Entries()
		digests := make([]string, 0, len(entries))
		for _, e := range entries {
			if err := w.WriteHeader(&e.Header); err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write(make([]byte, e.Header.Size)); err != nil {
				t.Fatal(err)
			}
			digests = append(digests, e.Digest)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		gz := new(bytes.Buffer)
		zw := gzip.NewWriter(gz)
		if _, err := zw.Write(tw.Bytes()); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		planned := readLayer(t, gz.Bytes())
		if len(planned) != len(written) {
			t.Fatalf("layer %d: %d entries planned, %d written", i, len(planned), len(written))
		}
		for j := range written {
			if diff := cmp.Diff(written[j].Header, planned[j].Header); diff != "" {
				t.Errorf("layer %d: %s: header differs from what Render writes (-written +planned):\n%s", i, written[j].Header.Name, diff)
			}
			want := ""
			if hasContent(&written[j].Header) {
				want = sha256Of([]byte(written[j].Content))
			}
			if digests[j] != want {
				t.Errorf("layer %d: %s: digest %q, want %q", i, written[j].Header.Name, digests[j], want)
			}
		}
	}
}

// TestLayerPlanReportedDigests checks that planning preserves reported
// digests regardless of algorithm and Render writes the content. Files
// written by the build get SHA-256 digests.
func TestLayerPlanReportedDigests(t *testing.T) {
	plans, content := planLayers(t, newContext(t, func(name string, _ []byte) string { return "test:" + name }))
	got := map[string]string{}
	written := map[string]string{}
	for _, p := range plans {
		for _, e := range p.Entries() {
			got[e.Header.Name] = e.Digest
		}
		b, _ := render(t, p, content)
		for _, e := range readLayer(t, b) {
			written[e.Header.Name] = e.Content
		}
	}
	for name, want := range map[string]string{
		"usr/bin/a":         "test:usr/bin/a",
		"usr/bin/b":         "test:usr/bin/b",
		"usr/share/b/data":  "test:usr/share/b/data", // chown keeps the content
		"etc/passwd":        sha256Of([]byte(written["etc/passwd"])),
		"usr/bin/a-alias":   "", // a hard link
		"usr/share/a/empty": "",
	} {
		if got[name] != want {
			t.Errorf("%s: digest %q, want %q", name, got[name], want)
		}
	}
	if written["usr/bin/b"] != "b binary, a bit longer than a's\n" {
		t.Errorf("usr/bin/b rendered as %q", written["usr/bin/b"])
	}
	if written["etc/passwd"] == "root:x:0:0:root:/root:/bin/sh\n" {
		t.Error("etc/passwd: the build did not rewrite it")
	}
}

func planDigests(t *testing.T, plans []*build.LayerPlan) [][sha256.Size]byte {
	t.Helper()
	out := make([][sha256.Size]byte, 0, len(plans))
	for _, p := range plans {
		d, err := p.Digest()
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, d)
	}
	return out
}

// TestLayerPlanDigest checks that the same build produces the same plan
// digests, that a different content digest changes the affected plan's
// digest, and that changing returned entries does not.
func TestLayerPlanDigest(t *testing.T) {
	plans, _ := planLayers(t, newContext(t, reportSHA256))
	base := planDigests(t, plans)
	again, _ := planLayers(t, newContext(t, reportSHA256))
	if diff := cmp.Diff(base, planDigests(t, again)); diff != "" {
		t.Errorf("the same build planned different digests (-first +second):\n%s", diff)
	}

	// A different digest for usr/bin/a changes a's layer and leaves b's
	// alone.
	changed, _ := planLayers(t, newContext(t, func(name string, data []byte) string {
		if name == "usr/bin/a" {
			return "test:changed"
		}
		return sha256Of(data)
	}))
	got := planDigests(t, changed)
	if got[0] == base[0] {
		t.Error("layer 0: the same digest with different usr/bin/a content")
	}
	if got[1] != base[1] {
		t.Error("layer 1: digest changed with no change to its content")
	}

	for _, e := range plans[0].Entries() {
		if e.Header.PAXRecords != nil {
			e.Header.PAXRecords["SCHILY.xattr.user.changed"] = "1"
		}
		e.Header.Name = "changed"
	}
	if d, err := plans[0].Digest(); err != nil || d != base[0] {
		t.Errorf("layer 0 digest after changing its Entries = %x, %v; want %x", d, err, base[0])
	}
}

// TestPlanLayersNeedsLayeredTar checks that PlanLayers rejects unlayered
// builds and EROFS output.
func TestPlanLayersNeedsLayeredTar(t *testing.T) {
	ctx := t.Context()
	unlayered, err := build.New(ctx, tarfs.New(), withIsolatedDirs(t,
		build.WithImageConfiguration(types.ImageConfiguration{Contents: types.ImageContents{BuildRepositories: []string{unusedRepository}}}),
		build.WithArch(types.ParseArchitecture("x86_64")),
		build.WithPreResolvedPackages(fakePackages(reportSHA256)),
	)...)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := unlayered.PlanLayers(ctx); err == nil {
		t.Error("unlayered build: got = nil, wanted an error")
	}

	if _, _, err := newContext(t, reportSHA256, build.WithFormat("erofs")).PlanLayers(ctx); err == nil {
		t.Error("erofs build: got = nil, wanted an error")
	}
}

// TestAPKLayerOrderSharedSource checks files reached through two paths that
// are both written as regular files, a paths hardlink mutation and an APK
// hard link whose name goes through a symlinked directory, and a hard link
// whose target goes through a symlinked directory.
func TestAPKLayerOrderSharedSource(t *testing.T) {
	t.Run("paths hardlink", func(t *testing.T) {
		// Sorting by path would put usr/bin/a1 between usr/bin/a and usr/bin/a2.
		plans := buildAndPlan(t, []apk.PackageContents{newPackage("a", "a", 100,
			dir("usr"), dir("usr/bin"),
			file("usr/bin/a", "a\n"),
			file("usr/bin/a1", "a1\n"),
		)}, types.PathMutation{Path: "usr/bin/a2", Type: "hardlink", Source: "usr/bin/a"})
		at := checkLayerPaths(t, plans, "a", "usr/bin/a", "usr/bin/a2", "usr/bin/a1")
		require.Equal(t, at["usr/bin/a"]+1, at["usr/bin/a2"], "usr/bin/a2 is not right after usr/bin/a")
	})
	t.Run("hard link through symlink", func(t *testing.T) {
		// bin/x and bin/y are both written as regular files under usr/bin;
		// sorting by path would put usr/bin/xa between them.
		plans := buildAndPlan(t, []apk.PackageContents{newPackage("a", "a", 100,
			dir("usr"), dir("usr/bin"),
			file("usr/bin/xa", "xa\n"),
			symlink("bin", "usr/bin"),
			file("bin/x", "x\n"),
			hardlink("bin/y", "bin/x"),
		)})
		at := checkLayerPaths(t, plans, "a", "usr/bin/xa", "usr/bin/x", "usr/bin/y")
		require.Equal(t, at["usr/bin/x"]+1, at["usr/bin/y"], "usr/bin/y is not right after usr/bin/x")
	})
	t.Run("hard link through symlink target", func(t *testing.T) {
		// usr/bin/zz sorts before usr/share/zdata by path but links through
		// the bin symlink, so it comes last.
		plans := buildAndPlan(t, []apk.PackageContents{newPackage("a", "a", 100,
			dir("etc"), dir("usr"), dir("usr/bin"), dir("usr/share"),
			file("usr/bin/a", "a\n"),
			file("usr/share/zdata", "z data\n"),
			file("etc/a.conf", "a=1\n"),
			symlink("bin", "usr/bin"),
			hardlink("usr/bin/zz", "bin/a"),
		)})
		checkLayerPaths(t, plans, "a", "usr/bin/a", "usr/share/zdata", "etc/a.conf", "usr/bin/zz")
	})
}

func TestAPKLayerOrderPreservesSymlinkAcrossLayers(t *testing.T) {
	tarBin, err := exec.LookPath("tar")
	if err != nil {
		t.Skip("tar is required to unpack the layers")
	}
	pkgs := []apk.PackageContents{
		newPackage("base", "base", 2000, dir("usr"), dir("usr/bin"), symlink("bin", "usr/bin")),
		newPackage("app", "app", 1000, dir("bin/"), file("bin/tool", "tool\n")),
	}
	plans, content := planLayers(t, orderedContext(t, pkgs))
	require.Len(t, plans, 3, "layers base, app, and the generated files")
	root := t.TempDir()
	tool := filepath.Join(root, "usr/bin/tool")
	for i, p := range plans {
		data, _ := render(t, p, content)
		// Creating device nodes requires privileges.
		cmd := exec.CommandContext(t.Context(), tarBin, "--exclude=dev", "--no-same-owner", "-xzf", "-")
		cmd.Dir = root
		cmd.Stdin = bytes.NewReader(data)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "unpacking layer %d: %s", i, out)

		target, err := os.Readlink(filepath.Join(root, "bin"))
		require.NoError(t, err, "bin after layer %d", i)
		require.Equal(t, "usr/bin", target, "bin after layer %d", i)
		if i == 0 {
			_, err := os.Lstat(tool)
			require.ErrorIs(t, err, fs.ErrNotExist, "usr/bin/tool after base's layer")
			continue
		}
		got, err := os.ReadFile(tool)
		require.NoError(t, err, "usr/bin/tool after layer %d", i)
		require.Equal(t, "tool\n", string(got), "usr/bin/tool after layer %d", i)
	}
}

// TestAPKLayerOrderFileConflict checks that two packages shipping different
// content at one path still fail the build with the order option.
func TestAPKLayerOrderFileConflict(t *testing.T) {
	pkgs := []apk.PackageContents{
		newPackage("one", "one", 2000, dir("usr"), dir("usr/bin"), file("usr/bin/tool", "one\n")),
		newPackage("two", "two", 1000, dir("usr"), dir("usr/bin"), file("usr/bin/tool", "two\n")),
	}
	_, err := orderedContext(t, pkgs).BuildLayers(t.Context())
	require.ErrorAs(t, err, &apk.FileConflictError{})
	_, _, err = orderedContext(t, pkgs).PlanLayers(t.Context())
	require.ErrorAs(t, err, &apk.FileConflictError{})
}
