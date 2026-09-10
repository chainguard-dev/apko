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

package tarfs

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"reflect"
	"strings"
	"testing"
	"time"
)

// fixtureTar writes the member shapes apk packages actually contain: a
// directory, a regular file with the apk checksum and an xattr as PAX records,
// a symlink, a hardlink, a member with a name too long for USTAR (which forces
// a PAX path record), and a file with explicit times.
func fixtureTar(t testing.TB) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	epoch := time.Unix(1700000000, 0)
	longName := "usr/share/" + strings.Repeat("verylongdirectoryname/", 6) + "file.txt"
	members := []struct {
		hdr  tar.Header
		body string
	}{
		// apk data tars name directories without a trailing slash.
		{hdr: tar.Header{Typeflag: tar.TypeDir, Name: "usr", Mode: 0o755, Uid: 0, Gid: 0, Uname: "root", Gname: "root", ModTime: epoch}},
		{hdr: tar.Header{Typeflag: tar.TypeDir, Name: "usr/bin", Mode: 0o755, Uid: 1, Gid: 2, Uname: "root", Gname: "root", ModTime: epoch}},
		{
			hdr: tar.Header{
				Typeflag: tar.TypeReg, Name: "usr/bin/hello", Mode: 0o4755, Uid: 1000, Gid: 1001, Uname: "root", Gname: "root", ModTime: epoch,
				Format: tar.FormatPAX,
				PAXRecords: map[string]string{
					"APK-TOOLS.checksum.SHA1":          "Q1abcdefghijklmnopqrstuvwxyz0123456789=",
					"SCHILY.xattr.security.capability": "\x01\x00\x00\x02\x00\x04\x00\x00",
					// Empty-valued records stay in PAXRecords but archive/tar
					// skips them before the Xattrs mirror.
					"SCHILY.xattr.user.empty": "",
				},
			},
			body: "hello world\n",
		},
		// Ownership above MaxInt32: the compact record must not narrow it.
		// 4294967294 is the user-namespace-mapped nobody in many container tars.
		{hdr: tar.Header{Typeflag: tar.TypeReg, Name: "usr/bin/bigids", Mode: 0o644, Uid: 4294967294, Gid: 3000000000, ModTime: epoch, Format: tar.FormatPAX}, body: "big\n"},
		// Device nodes carry the only nonzero Devmajor/Devminor in the fixture.
		{hdr: tar.Header{Typeflag: tar.TypeChar, Name: "dev/null", Mode: 0o666, Devmajor: 1, Devminor: 3, ModTime: epoch}},
		{hdr: tar.Header{Typeflag: tar.TypeBlock, Name: "dev/loop0", Mode: 0o660, Devmajor: 7, Devminor: 0, ModTime: epoch}},
		{hdr: tar.Header{Typeflag: tar.TypeFifo, Name: "dev/initctl", Mode: 0o600, ModTime: epoch}},
		{hdr: tar.Header{Typeflag: tar.TypeReg, Name: "usr/bin/gnu", Mode: 0o644, Uid: 500, Gid: 501, ModTime: epoch, Format: tar.FormatGNU}, body: "gnu\n"},
		{hdr: tar.Header{Typeflag: tar.TypeSymlink, Name: "usr/bin/hi", Linkname: "hello", Mode: 0o777, Uname: "root", Gname: "root", ModTime: epoch}},
		{hdr: tar.Header{Typeflag: tar.TypeLink, Name: "usr/bin/hello-hard", Linkname: "usr/bin/hello", Mode: 0o755, Uname: "root", Gname: "root", ModTime: epoch}},
		{hdr: tar.Header{Typeflag: tar.TypeReg, Name: longName, Mode: 0o644, Uname: "nobody", Gname: "nogroup", ModTime: epoch, Format: tar.FormatPAX}, body: "long\n"},
		{
			hdr:  tar.Header{Typeflag: tar.TypeReg, Name: "usr/bin/timed", Mode: 0o644, ModTime: epoch, AccessTime: epoch.Add(time.Hour), ChangeTime: epoch.Add(2 * time.Hour), Format: tar.FormatPAX},
			body: "timed\n",
		},
	}
	for _, m := range members {
		m.hdr.Size = int64(len(m.body))
		if err := tw.WriteHeader(&m.hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(tw, m.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// readHeaders is the reference: what archive/tar itself produces for the same bytes.
func readHeaders(t testing.TB, data []byte) []tar.Header {
	t.Helper()
	var out []tar.Header
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, *hdr)
	}
}

func TestEntriesRoundTripHeaders(t *testing.T) {
	data := fixtureTar(t)
	want := readHeaders(t, data)

	fsys, err := New(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	got := fsys.Entries()
	if len(got) != len(want) {
		t.Fatalf("Entries: got %d, want %d", len(got), len(want))
	}
	for i := range want {
		if !reflect.DeepEqual(got[i].Header, want[i]) {
			t.Errorf("entry %d (%s): header differs\n got: %+v\nwant: %+v", i, want[i].Name, got[i].Header, want[i])
		}
	}

	// Materialized headers are independent copies; mutating one must not leak
	// into the index or into the next caller. Xattrs is a separately allocated
	// map, so it needs its own check.
	got[2].Header.PAXRecords["APK-TOOLS.checksum.SHA1"] = "tampered"
	got[2].Header.Xattrs["security.capability"] = "tampered" //nolint:staticcheck // mirrors archive/tar
	again := fsys.Entries()[2]
	if again.Header.PAXRecords["APK-TOOLS.checksum.SHA1"] == "tampered" {
		t.Error("Entries() shares PAX map state between calls")
	}
	if again.Header.Xattrs["security.capability"] == "tampered" { //nolint:staticcheck // mirrors archive/tar
		t.Error("Entries() shares Xattrs map state between calls")
	}

	// The exported Entry's fs.DirEntry methods read the shared index record;
	// they must agree with the same archive/tar reference the headers do.
	for i, e := range got {
		ref := want[i].FileInfo()
		if e.Name() != ref.Name() || e.Size() != ref.Size() || e.Type() != ref.Mode() || e.IsDir() != ref.IsDir() {
			t.Errorf("entry %d (%s): DirEntry methods = {%s %d %v %v}, want {%s %d %v %v}", i, want[i].Name,
				e.Name(), e.Size(), e.Type(), e.IsDir(), ref.Name(), ref.Size(), ref.Mode(), ref.IsDir())
		}
		info, err := e.Info()
		if err != nil || info.Name() != ref.Name() {
			t.Errorf("entry %d (%s): Info() = %v, %v", i, want[i].Name, info, err)
		}
	}
}

func TestFileInfoMatchesArchiveTar(t *testing.T) {
	data := fixtureTar(t)
	want := readHeaders(t, data)

	fsys, err := New(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	for _, hdr := range want {
		ref := hdr.FileInfo()
		fi, err := fsys.Stat(hdr.Name)
		if err != nil {
			t.Fatalf("Stat(%q): %v", hdr.Name, err)
		}
		if fi.Name() != ref.Name() || fi.Size() != ref.Size() || fi.Mode() != ref.Mode() || !fi.ModTime().Equal(ref.ModTime()) || fi.IsDir() != ref.IsDir() {
			t.Errorf("Stat(%q) = {%s %d %v %v %v}, want {%s %d %v %v %v}", hdr.Name,
				fi.Name(), fi.Size(), fi.Mode(), fi.ModTime(), fi.IsDir(),
				ref.Name(), ref.Size(), ref.Mode(), ref.ModTime(), ref.IsDir())
		}
		sys, ok := fi.Sys().(*tar.Header)
		if !ok {
			t.Errorf("Stat(%q).Sys() = %T, want *tar.Header", hdr.Name, fi.Sys())
		} else if !reflect.DeepEqual(*sys, hdr) {
			t.Errorf("Stat(%q).Sys() = %+v, want %+v", hdr.Name, *sys, hdr)
		}
		// archive/tar's headerFileInfo formats via fs.FormatFileInfo; the
		// index record has to keep that or %v output changes for callers.
		if got, want := fmt.Sprint(fi), fmt.Sprint(ref); got != want {
			t.Errorf("Stat(%q) String() = %q, want %q", hdr.Name, got, want)
		}
	}
}

// BenchmarkNew reports the indexing cost the compact record targets. Run with
// -benchmem; B/op here is allocation volume, not the resident size the record
// actually reduces, which needs a heap profile to see.
func BenchmarkNew(b *testing.B) {
	data := fixtureTar(b)
	r := bytes.NewReader(data)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := New(r, int64(len(data))); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkOpen covers the per-file read path, which materializes an Entry
// because Entry.Header is an exported value field.
func BenchmarkOpen(b *testing.B) {
	data := fixtureTar(b)
	fsys, err := New(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := fsys.Open("usr/bin/hello"); err != nil {
			b.Fatal(err)
		}
	}
}

func TestOpenStatReadDirReadlink(t *testing.T) {
	data := fixtureTar(t)
	fsys, err := New(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}

	f, err := fsys.Open("usr/bin/hello")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "hello world\n" {
		t.Errorf("Open(hello) body = %q", body)
	}
	if got := f.(*File).Entry.Header.PAXRecords["APK-TOOLS.checksum.SHA1"]; !strings.HasPrefix(got, "Q1") {
		t.Errorf("File.Entry header lost its PAX checksum: %q", got)
	}
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&fs.ModeSetuid == 0 || st.Mode().Perm() != 0o755 {
		t.Errorf("Stat(hello).Mode() = %v, want setuid 0755", st.Mode())
	}

	lf, err := fsys.Open("usr/bin/hi")
	if err != nil {
		t.Fatalf("Open(hi): %v", err)
	}
	b, err := io.ReadAll(lf)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "hello world\n" {
		t.Errorf("Open(hi) body = %q, want symlink target content", b)
	}
	for name, want := range map[string]string{"usr/bin/hi": "hello", "usr/bin/hello-hard": "usr/bin/hello"} {
		link, err := fsys.Readlink(name)
		if err != nil || link != want {
			t.Errorf("Readlink(%q) = %q, %v, want %q", name, link, err, want)
		}
	}
	if _, err := fsys.Readlink("usr/bin/hello"); err == nil {
		t.Error("Readlink on a regular file should fail")
	}

	entries, err := fsys.ReadDir("usr/bin")
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
		info, err := e.Info()
		if err != nil || info.Name() != e.Name() {
			t.Errorf("DirEntry %q Info() = %v, %v", e.Name(), info, err)
		}
	}
	want := []string{"bigids", "gnu", "hello", "hello-hard", "hi", "timed"}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("ReadDir(usr/bin) = %v, want %v", names, want)
	}

	if _, err := fsys.Stat("nope"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Stat(nope) = %v, want ErrNotExist", err)
	}
	if root, err := fsys.Stat("."); err != nil || !root.IsDir() {
		t.Errorf("Stat(.) = %v, %v, want synthesized root dir", root, err)
	}
}
