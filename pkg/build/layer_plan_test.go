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
	"hash"
	"io"
	"io/fs"
	"maps"
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

// fakePackages returns three packages from two origins with xattrs, a
// symlink, a hard link, an empty file, and etc/passwd for the build to
// rewrite.
func fakePackages(report func(name string, data []byte) string) []apk.PackageContents {
	at := func(sec int64) time.Time { return time.Unix(sec, 0).UTC() }
	pkg := func(name, origin string, size uint64, hdrs ...any) apk.PackageContents {
		p := fakePackage{
			info:   &apktypes.PackageInfo{Name: name, Origin: origin, Version: "1", Size: size},
			files:  fstest.MapFS{},
			report: report,
		}
		for i := 0; i < len(hdrs); i++ {
			hdr := hdrs[i].(tar.Header)
			if hdr.Typeflag == tar.TypeReg {
				i++
				p.files[hdr.Name] = &fstest.MapFile{Data: []byte(hdrs[i].(string)), Mode: 0o644}
			}
			p.entries = append(p.entries, hdr)
		}
		return p
	}
	reg := func(name, content string, mtime int64, pax map[string]string) (tar.Header, string) {
		sum := sha1.Sum([]byte(content)) //nolint:gosec
		records := map[string]string{"APK-TOOLS.checksum.SHA1": hex.EncodeToString(sum[:])}
		maps.Copy(records, pax)
		return tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0o644, Size: int64(len(content)), ModTime: at(mtime), PAXRecords: records}, content
	}
	dir := func(name string, mtime int64) tar.Header {
		return tar.Header{Typeflag: tar.TypeDir, Name: name, Mode: 0o755, ModTime: at(mtime)}
	}

	aBin, aBinData := reg("usr/bin/a", "a binary\n", 100, map[string]string{"SCHILY.xattr.security.capability": "\x01\x00\x00\x02"})
	aConf, aConfData := reg("etc/a.conf", "a=1\n", 120, nil)
	aPasswd, aPasswdData := reg("etc/passwd", "root:x:0:0:root:/root:/bin/sh\n", 125, nil)
	aEmpty, aEmptyData := reg("usr/share/a/empty", "", 130, nil)
	bBin, bBinData := reg("usr/bin/b", "b binary, a bit longer than a's\n", 200, nil)
	bShare, bShareData := reg("usr/share/b/data", "b data", 210, nil)
	bInc, bIncData := reg("usr/include/b.h", "#define B 1\n", 300, nil)
	return []apk.PackageContents{
		pkg("a", "a", 3000,
			dir("etc", 10), dir("usr", 11), dir("usr/bin", 12), dir("usr/share", 14), dir("usr/share/a", 15),
			aBin, aBinData, aConf, aConfData, aPasswd, aPasswdData, aEmpty, aEmptyData,
			tar.Header{Typeflag: tar.TypeSymlink, Name: "usr/bin/a-link", Linkname: "a", ModTime: at(101), PAXRecords: map[string]string{"APK-TOOLS.checksum.SHA1": hex.EncodeToString(make([]byte, 20))}},
			tar.Header{Typeflag: tar.TypeLink, Name: "usr/bin/a-alias", Linkname: "usr/bin/a", ModTime: at(100)},
		),
		pkg("b", "b", 2000, dir("usr", 21), dir("usr/bin", 22), dir("usr/share", 23), dir("usr/share/b", 24), bBin, bBinData, bShare, bShareData),
		pkg("b-dev", "b", 100, dir("usr", 31), dir("usr/include", 32), bInc, bIncData),
	}
}

// unusedRepository names a repository that builds with pre-resolved
// packages do not read.
const unusedRepository = "/nonexistent/layer-plans"

// newContext configures a layered build of fakePackages that adds a user,
// rewrites etc/passwd, and changes the ownership of usr/share/b/data.
func newContext(t *testing.T, report func(name string, data []byte) string, opts ...build.Option) *build.Context {
	t.Helper()
	uid, gid := uint32(65532), uint32(65532)
	ic := types.ImageConfiguration{
		Contents: types.ImageContents{Repositories: []string{unusedRepository}},
		Accounts: types.ImageAccounts{
			Users:  []types.User{{UserName: "nonroot", UID: uid, GID: &gid, HomeDir: "/home/nonroot"}},
			Groups: []types.Group{{GroupName: "nonroot", GID: gid}},
		},
		Paths:    []types.PathMutation{{Path: "usr/share/b/data", Type: "permissions", UID: &uid, GID: &gid, Permissions: 0o644}},
		Layering: &types.Layering{Strategy: "origin", Budget: 2},
	}
	bc, err := build.New(t.Context(), tarfs.New(), withIsolatedDirs(t, append([]build.Option{
		build.WithImageConfiguration(ic),
		build.WithArch(types.ParseArchitecture("x86_64")),
		build.WithSourceDateEpoch(time.Unix(1700000000, 0).UTC()),
		build.WithPreResolvedPackages(fakePackages(report)),
	}, opts...)...)...)
	if err != nil {
		t.Fatal(err)
	}
	return bc
}

func planLayers(t *testing.T, bc *build.Context) ([]*build.LayerPlan, *build.LayerContent) {
	t.Helper()
	plans, content, err := bc.PlanLayers(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return plans, content
}

func render(t *testing.T, p *build.LayerPlan, content *build.LayerContent, opts ...build.RenderOption) ([]byte, *build.LayerDigests) {
	t.Helper()
	var buf bytes.Buffer
	d, err := p.Render(t.Context(), content, &buf, opts...)
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

// archiveReaders returns package readers that serve pkgs' members. They fail
// if a package is opened twice or its members are not read in increasing
// archive order. A repeated name refers to its last occurrence. Use one
// option per render.
func archiveReaders(pkgs []apk.PackageContents, newHash func(string) (hash.Hash, bool)) build.RenderOption {
	archives := map[string]fakePackage{}
	for _, pc := range pkgs {
		p := pc.(fakePackage)
		archives[p.info.Name] = p
	}
	opened := map[string]bool{}
	open := 0
	return build.WithPackageReaders(func(pkg *apk.Package) (build.PackageReader, error) {
		if open != 0 {
			return nil, fmt.Errorf("opening package %s with another reader open", pkg.Name)
		}
		p, ok := archives[pkg.Name]
		if !ok {
			return nil, fmt.Errorf("no package %s", pkg.Name)
		}
		if opened[pkg.Name] {
			return nil, fmt.Errorf("package %s opened twice", pkg.Name)
		}
		opened[pkg.Name] = true
		open++
		return &archiveReader{pkg: p, close: func() { open-- }}, nil
	}, newHash)
}

type archiveReader struct {
	pkg   fakePackage
	last  int
	close func()
}

func (r *archiveReader) Open(member string) (io.ReadCloser, error) {
	pos := 0
	for i, h := range r.pkg.entries {
		if h.Name == member {
			pos = i + 1
		}
	}
	if pos == 0 {
		return nil, fmt.Errorf("package %s has no member %s", r.pkg.info.Name, member)
	}
	if pos <= r.last {
		return nil, fmt.Errorf("package %s: read %s at position %d after position %d", r.pkg.info.Name, member, pos, r.last)
	}
	r.last = pos
	return io.NopCloser(bytes.NewReader(r.pkg.files[member].Data)), nil
}

func (r *archiveReader) Close() error {
	r.close()
	return nil
}

// withCopy adds to the named package a file with the same content as from,
// which may be in another package.
func withCopy(pkgs []apk.PackageContents, pkgName, name, from string) []apk.PackageContents {
	var data []byte
	var src tar.Header
	for _, pc := range pkgs {
		p := pc.(fakePackage)
		for _, h := range p.entries {
			if h.Name == from {
				data, src = p.files[from].Data, h
			}
		}
	}
	for i, pc := range pkgs {
		p := pc.(fakePackage)
		if p.info.Name != pkgName {
			continue
		}
		hdr := src
		hdr.Name = name
		p.entries = append(slices.Clone(p.entries), hdr)
		p.files = maps.Clone(p.files)
		p.files[name] = &fstest.MapFile{Data: data, Mode: 0o644}
		pkgs[i] = p
	}
	return pkgs
}

func TestAPKLayerOrder(t *testing.T) {
	ctx := t.Context()
	// b-dev's copy of b's data puts identical bytes in two packages of one layer.
	pkgs := withCopy(fakePackages(reportSHA256), "b-dev", "usr/include/c-data", "usr/share/b/data")
	ordered := []build.Option{build.WithPreResolvedPackages(pkgs), build.WithAPKLayerOrder(true)}
	normal, err := newContext(t, reportSHA256, build.WithPreResolvedPackages(pkgs)).BuildLayers(ctx)
	require.NoError(t, err)
	reordered, err := newContext(t, reportSHA256, ordered...).BuildLayers(ctx)
	require.NoError(t, err)
	plans, content := planLayers(t, newContext(t, reportSHA256, ordered...))
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
		require.Equal(t, builtDigest, digests.Digest)
		// Reading packages forward produces the same layer, including the
		// rewritten etc/passwd, which still comes from the LayerContent.
		_, streamed := render(t, plans[i], content, archiveReaders(pkgs, nil))
		require.Equal(t, builtDigest, streamed.Digest, "layer %d read from packages", i)

		var paths []string
		for _, e := range plans[i].Entries() {
			paths = append(paths, e.Header.Name)
		}
		if slices.Contains(paths, "usr/bin/a-alias") {
			require.Less(t, slices.Index(paths, "usr/bin/a"), slices.Index(paths, "etc/a.conf"))
			require.Less(t, slices.Index(paths, "usr/bin/a"), slices.Index(paths, "usr/bin/a-alias"))
		}
	}
}

// A name repeated in an APK is ordered by its last occurrence, which is the
// one a package filesystem opens.
func TestAPKLayerOrderRepeatedName(t *testing.T) {
	pkgs := fakePackages(reportSHA256)
	p := pkgs[0].(fakePackage)
	for _, h := range p.entries {
		if h.Name == "usr/bin/a" {
			p.entries = append(p.entries, h)
			break
		}
	}
	pkgs[0] = p
	opts := []build.Option{build.WithPreResolvedPackages(pkgs), build.WithAPKLayerOrder(true)}
	layers, err := newContext(t, reportSHA256, opts...).BuildLayers(t.Context())
	require.NoError(t, err)
	plans, content := planLayers(t, newContext(t, reportSHA256, opts...))
	for i, layer := range layers {
		want, err := layer.Digest()
		require.NoError(t, err)
		_, got := render(t, plans[i], content, archiveReaders(pkgs, nil))
		require.Equal(t, want, got.Digest, "layer %d", i)
	}
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

// TestRenderChecksPackageContent checks that Render verifies content from
// package readers, hashing digests other than sha256 with the caller's hash.
func TestRenderChecksPackageContent(t *testing.T) {
	reportSHA1 := func(_ string, data []byte) string { return fmt.Sprintf("sha1:%x", sha1.Sum(data)) } //nolint:gosec
	newSHA1 := func(algorithm string) (hash.Hash, bool) { return sha1.New(), algorithm == "sha1" }     //nolint:gosec
	for _, tc := range []struct {
		name    string
		report  func(string, []byte) string
		newHash func(string) (hash.Hash, bool)
		corrupt bool
		wantErr string
	}{
		{name: "sha256", report: reportSHA256},
		{name: "caller hash", report: reportSHA1, newHash: newSHA1},
		{name: "no hash", report: reportSHA1, wantErr: "cannot check sha1 digests"},
		{name: "mismatch", report: reportSHA256, corrupt: true, wantErr: "content has sha256 digest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ordered := build.WithAPKLayerOrder(true)
			layers, err := newContext(t, tc.report, ordered).BuildLayers(t.Context())
			require.NoError(t, err)
			plans, content := planLayers(t, newContext(t, tc.report, ordered))
			served := fakePackages(tc.report)
			if tc.corrupt {
				for i, pc := range served {
					p := pc.(fakePackage)
					p.files = maps.Clone(p.files)
					for name, f := range p.files {
						p.files[name] = &fstest.MapFile{Data: bytes.ToUpper(f.Data), Mode: f.Mode}
					}
					served[i] = p
				}
			}
			var errs []error
			for i, p := range plans {
				d, err := p.Render(t.Context(), content, io.Discard, archiveReaders(served, tc.newHash))
				if err != nil {
					errs = append(errs, err)
					continue
				}
				want, err := layers[i].Digest()
				require.NoError(t, err)
				require.Equal(t, want, d.Digest, "layer %d", i)
			}
			if tc.wantErr == "" {
				require.NoError(t, errors.Join(errs...))
			} else {
				require.ErrorContains(t, errors.Join(errs...), tc.wantErr)
			}
		})
	}
}

// TestAPKLayerOrderSharedSource checks files reached through two paths that
// are both written as regular files, a paths hardlink mutation and an APK
// hard link whose name goes through a symlinked directory, and a hard link
// whose target goes through a symlinked directory.
func TestAPKLayerOrderSharedSource(t *testing.T) {
	ic := types.ImageConfiguration{
		Contents: types.ImageContents{Repositories: []string{unusedRepository}},
		Paths:    []types.PathMutation{{Path: "usr/bin/a2", Type: "hardlink", Source: "usr/bin/a"}},
		Layering: &types.Layering{Strategy: "origin", Budget: 2},
	}
	symlinked := fakePackages(reportSHA256)
	p := symlinked[0].(fakePackage)
	var bin tar.Header
	for _, h := range p.entries {
		if h.Name == "usr/bin/a" {
			bin = h
		}
	}
	reg := bin
	reg.Name = "bin/x"
	p.files["bin/x"] = p.files["usr/bin/a"]
	p.entries = append(p.entries,
		tar.Header{Typeflag: tar.TypeSymlink, Name: "bin", Linkname: "usr/bin", PAXRecords: bin.PAXRecords},
		reg,
		tar.Header{Typeflag: tar.TypeLink, Name: "bin/y", Linkname: "bin/x"},
	)
	symlinked[0] = p

	// A hard link reached through a symlinked directory, in a package whose
	// archive order differs from path order around it.
	barrier := fakePackages(reportSHA256)
	p = barrier[0].(fakePackage)
	data := bin
	data.Name = "usr/share/a/zdata"
	p.files["usr/share/a/zdata"] = &fstest.MapFile{Data: []byte("z data\n"), Mode: 0o644}
	sum := sha1.Sum(p.files["usr/share/a/zdata"].Data) //nolint:gosec
	data.Size = int64(len(p.files["usr/share/a/zdata"].Data))
	data.PAXRecords = map[string]string{"APK-TOOLS.checksum.SHA1": hex.EncodeToString(sum[:])}
	var entries []tar.Header
	for _, h := range p.entries {
		if h.Name == "etc/a.conf" {
			entries = append(entries, data)
		}
		entries = append(entries, h)
	}
	entries = append(entries,
		tar.Header{Typeflag: tar.TypeSymlink, Name: "bin", Linkname: "usr/bin", PAXRecords: bin.PAXRecords},
		tar.Header{Typeflag: tar.TypeLink, Name: "usr/bin/zz", Linkname: "bin/a"},
	)
	p.entries = entries
	barrier[0] = p

	for name, tc := range map[string]struct {
		pkgs []apk.PackageContents
		opts []build.Option
	}{
		"hard link through symlink target": {pkgs: barrier, opts: []build.Option{build.WithPreResolvedPackages(barrier)}},
		"paths hardlink":                   {pkgs: fakePackages(reportSHA256), opts: []build.Option{build.WithImageConfiguration(ic)}},
		"hard link through symlink":        {pkgs: symlinked, opts: []build.Option{build.WithPreResolvedPackages(symlinked)}},
	} {
		t.Run(name, func(t *testing.T) {
			opts := append(slices.Clone(tc.opts), build.WithAPKLayerOrder(true))
			layers, err := newContext(t, reportSHA256, opts...).BuildLayers(t.Context())
			require.NoError(t, err)
			plans, content := planLayers(t, newContext(t, reportSHA256, opts...))
			for i, layer := range layers {
				want, err := layer.Digest()
				require.NoError(t, err)
				_, got := render(t, plans[i], content, archiveReaders(tc.pkgs, nil))
				require.Equal(t, want, got.Digest, "layer %d", i)
			}
		})
	}
}
