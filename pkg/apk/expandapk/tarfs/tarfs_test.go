// Copyright 2026 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
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
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"
	"time"
)

// writeTar serialises headers (with content for regular files) and returns
// the archive bytes.
func writeTar(t *testing.T, hdrs []tar.Header, contents map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for i := range hdrs {
		hdr := hdrs[i]
		if err := tw.WriteHeader(&hdr); err != nil {
			t.Fatalf("WriteHeader(%q): %v", hdr.Name, err)
		}
		if body := contents[hdr.Name]; len(body) > 0 {
			if _, err := tw.Write(body); err != nil {
				t.Fatalf("Write(%q): %v", hdr.Name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// readHeaders is the reference: what archive/tar yields for the same bytes.
func readHeaders(t *testing.T, data []byte) []*tar.Header {
	t.Helper()
	tr := tar.NewReader(bytes.NewReader(data))
	var out []*tar.Header
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, hdr)
	}
}

func newFS(t *testing.T, data []byte) *FS {
	t.Helper()
	fsys, err := New(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	return fsys
}

// checkEntry compares an indexed Entry against the header archive/tar
// produced for the same member, both as a Header and as a FileInfo.
func checkEntry(t *testing.T, e *Entry, want *tar.Header) {
	t.Helper()
	got := e.Header()
	// Nothing in apk writes these; Header documents that they are dropped.
	want.AccessTime, want.ChangeTime = time.Time{}, time.Time{}
	// archive/tar fills the deprecated Xattrs mirror of SCHILY.xattr.*
	// records. Callers read PAXRecords, so the mirror is not reconstructed.
	want.Xattrs = nil //nolint:staticcheck // clearing the deprecated field
	if !reflect.DeepEqual(got, *want) {
		t.Errorf("Header() mismatch for %q\n got: %+v\nwant: %+v", want.Name, got, *want)
	}

	fi := want.FileInfo()
	if e.Name() != fi.Name() {
		t.Errorf("%q: Name() = %q, want %q", want.Name, e.Name(), fi.Name())
	}
	if e.Size() != fi.Size() {
		t.Errorf("%q: Size() = %d, want %d", want.Name, e.Size(), fi.Size())
	}
	if e.Mode() != fi.Mode() {
		t.Errorf("%q: Mode() = %v, want %v", want.Name, e.Mode(), fi.Mode())
	}
	if e.Type() != fi.Mode().Type() {
		t.Errorf("%q: Type() = %v, want %v", want.Name, e.Type(), fi.Mode().Type())
	}
	if !e.ModTime().Equal(fi.ModTime()) || e.ModTime().IsZero() != fi.ModTime().IsZero() {
		t.Errorf("%q: ModTime() = %v, want %v", want.Name, e.ModTime(), fi.ModTime())
	}
	if e.IsDir() != fi.IsDir() {
		t.Errorf("%q: IsDir() = %v, want %v", want.Name, e.IsDir(), fi.IsDir())
	}
	sys, ok := e.Sys().(*tar.Header)
	if !ok {
		t.Fatalf("%q: Sys() is %T, want *tar.Header", want.Name, e.Sys())
	}
	if !reflect.DeepEqual(*sys, got) {
		t.Errorf("%q: Sys() disagrees with Header()", want.Name)
	}
	info, err := e.Info()
	if err != nil || info != fs.FileInfo(e) {
		t.Errorf("%q: Info() = %v, %v, want the entry itself", want.Name, info, err)
	}
}

func TestFixtures(t *testing.T) {
	mtime := time.Unix(1700000000, 0)
	sum := strings.Repeat("ab", 20)
	hdrs := []tar.Header{
		{Typeflag: tar.TypeDir, Name: "usr", Mode: 0o755, Uname: "root", Gname: "root", ModTime: mtime, Format: tar.FormatPAX},
		{Typeflag: tar.TypeDir, Name: "usr/bin", Mode: 0o755, Uname: "root", Gname: "root", ModTime: mtime, Format: tar.FormatPAX},
		{
			Typeflag: tar.TypeReg, Name: "usr/bin/su", Mode: 0o4755, Size: 5, Uname: "root", Gname: "root", ModTime: mtime, Format: tar.FormatPAX,
			PAXRecords: map[string]string{paxChecksumKey: sum, "SCHILY.xattr.security.capability": "\x01\x00\x00\x02"},
		},
		{
			// Uppercase checksum spelling must round-trip verbatim rather than
			// being normalised through the decoded field.
			Typeflag: tar.TypeReg, Name: "usr/bin/upper", Mode: 0o644, Size: 2, Uname: "root", Gname: "root", ModTime: mtime, Format: tar.FormatPAX,
			PAXRecords: map[string]string{paxChecksumKey: strings.ToUpper(sum)},
		},
		{
			// apk-tools' Q1 form is not hex at all.
			Typeflag: tar.TypeReg, Name: "usr/bin/q1", Mode: 0o644, Uname: "root", Gname: "root", ModTime: mtime, Format: tar.FormatPAX,
			PAXRecords: map[string]string{paxChecksumKey: "Q1" + sum[:38]},
		},
		{Typeflag: tar.TypeSymlink, Name: "usr/bin/sh", Linkname: "su", Mode: 0o777, Uname: "root", Gname: "root", ModTime: mtime, Format: tar.FormatPAX},
		// Absolute link targets are not resolvable through Open (pre-existing:
		// the index has no leading slash), but must still round-trip.
		{Typeflag: tar.TypeSymlink, Name: "usr/bin/abs", Linkname: "/usr/bin/su", Mode: 0o777, Uname: "root", Gname: "root", ModTime: mtime, Format: tar.FormatPAX},
		// Hardlink targets are joined relative to the member's directory
		// (pre-existing), so this one is not resolvable through Open either.
		{Typeflag: tar.TypeLink, Name: "usr/bin/hard", Linkname: "usr/bin/su", Mode: 0o644, Uname: "root", Gname: "root", ModTime: mtime, Format: tar.FormatPAX},
		{Typeflag: tar.TypeReg, Name: "usr/bin/" + strings.Repeat("longname", 20), Mode: 0o644, Uname: "root", Gname: "root", ModTime: mtime, Format: tar.FormatPAX},
		{Typeflag: tar.TypeReg, Name: "usr/bin/bigids", Mode: 0o644, Uid: 1 << 31, Gid: 1<<32 - 2, ModTime: mtime, Format: tar.FormatPAX},
		{Typeflag: tar.TypeDir, Name: "dev", Mode: 0o755, Uname: "root", Gname: "root", ModTime: mtime, Format: tar.FormatPAX},
		{Typeflag: tar.TypeDir, Name: "run", Mode: 0o755, Uname: "root", Gname: "root", ModTime: mtime, Format: tar.FormatPAX},
		{Typeflag: tar.TypeDir, Name: "etc", Mode: 0o755, Uname: "root", Gname: "root", ModTime: mtime, Format: tar.FormatPAX},
		{Typeflag: tar.TypeChar, Name: "dev/null", Mode: 0o666, Devmajor: 1, Devminor: 3, Uname: "root", Gname: "root", ModTime: mtime, Format: tar.FormatPAX},
		{Typeflag: tar.TypeBlock, Name: "dev/sda", Mode: 0o660, Devmajor: 8, Devminor: 0, Uname: "root", Gname: "disk", ModTime: mtime, Format: tar.FormatPAX},
		{Typeflag: tar.TypeFifo, Name: "run/fifo", Mode: 0o600, Uname: "root", Gname: "root", ModTime: mtime, Format: tar.FormatPAX},
		{Typeflag: tar.TypeReg, Name: "etc/sticky", Mode: 0o1644 | 0o2000, Uname: "root", Gname: "root", ModTime: mtime, Format: tar.FormatPAX},
		{Typeflag: tar.TypeReg, Name: "etc/gnu", Mode: 0o644, Uname: "root", Gname: "root", ModTime: mtime, Format: tar.FormatGNU},
		// Trailing-slash directory name, as some tar writers emit. Not walked
		// into below: tarfs indexes names verbatim, so "opt/" and "opt" differ.
		{Typeflag: tar.TypeDir, Name: "opt/", Mode: 0o755, Uname: "root", Gname: "root", ModTime: mtime, Format: tar.FormatPAX},
		{Typeflag: tar.TypeReg, Name: "etc/emptyxattr", Mode: 0o644, Uname: "root", Gname: "root", ModTime: mtime, Format: tar.FormatPAX, PAXRecords: map[string]string{"SCHILY.xattr.user.empty": ""}},
	}
	contents := map[string][]byte{"usr/bin/su": []byte("hello"), "usr/bin/upper": []byte("hi")}
	data := writeTar(t, hdrs, contents)
	want := readHeaders(t, data)
	fsys := newFS(t, data)

	entries := fsys.Entries()
	if len(entries) != len(want) {
		t.Fatalf("Entries() returned %d, want %d", len(entries), len(want))
	}
	for i, e := range entries {
		checkEntry(t, e, want[i])
	}

	t.Run("checksum", func(t *testing.T) {
		e := entries[2]
		got, ok := e.Checksum()
		if !ok || hex.EncodeToString(got) != sum {
			t.Errorf("Checksum() = %x, %v", got, ok)
		}
		if _, ok := entries[3].Checksum(); ok {
			t.Error("uppercase checksum must not decode")
		}
		if _, ok := entries[4].Checksum(); ok {
			t.Error("Q1 checksum must not decode")
		}
	})

	t.Run("header maps are independent", func(t *testing.T) {
		a, b := entries[2].Header(), entries[2].Header()
		a.PAXRecords["x"] = "y"
		if _, leaked := b.PAXRecords["x"]; leaked {
			t.Error("PAXRecords shared between Header() calls")
		}
	})

	t.Run("open and read", func(t *testing.T) {
		for _, name := range []string{"usr/bin/su", "usr/bin/sh"} {
			f, err := fsys.Open(name)
			if err != nil {
				t.Fatalf("Open(%q): %v", name, err)
			}
			body, err := io.ReadAll(f)
			if err != nil || string(body) != "hello" {
				t.Errorf("Open(%q) read %q, %v", name, body, err)
			}
			st, err := f.Stat()
			if err != nil || st.Name() != "su" {
				t.Errorf("Open(%q).Stat() = %v, %v", name, st, err)
			}
			f.Close()
		}
		if _, err := fsys.Open("nope"); err == nil {
			t.Error("Open(nope) succeeded")
		}
	})

	t.Run("stat", func(t *testing.T) {
		st, err := fsys.Stat("usr/bin/sh")
		if err != nil || st.Mode().Type() != fs.ModeSymlink {
			t.Errorf("Stat(symlink) = %v, %v", st, err)
		}
		root, err := fsys.Stat(".")
		if err != nil || !root.IsDir() {
			t.Errorf("Stat(.) = %v, %v", root, err)
		}
	})

	t.Run("readlink", func(t *testing.T) {
		if l, err := fsys.Readlink("usr/bin/sh"); err != nil || l != "su" {
			t.Errorf("Readlink = %q, %v", l, err)
		}
		if _, err := fsys.Readlink("usr/bin/su"); err == nil {
			t.Error("Readlink on regular file succeeded")
		}
	})

	t.Run("walkdir", func(t *testing.T) {
		var seen []string
		err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if p != "." {
				seen = append(seen, p)
				if _, ok := d.(*Entry); !ok {
					t.Errorf("%q: DirEntry is %T", p, d)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		// Every member except the trailing-slash "opt/" is reachable.
		if len(seen) != len(want)-1 {
			t.Errorf("WalkDir visited %d entries, want %d: %v", len(seen), len(want)-1, seen)
		}
	})
}

// TestRoundTripProperty generates headers across the field space and checks
// every indexed entry against what archive/tar reads back from the same
// bytes.
func TestRoundTripProperty(t *testing.T) {
	typeflags := []byte{tar.TypeReg, tar.TypeDir, tar.TypeSymlink, tar.TypeLink, tar.TypeChar, tar.TypeBlock, tar.TypeFifo}
	formats := []tar.Format{tar.FormatUnknown, tar.FormatUSTAR, tar.FormatPAX, tar.FormatGNU}
	names := []string{"root", "", "nobody", "someuser"}

	for seed := range 200 {
		rng := rand.New(rand.NewPCG(uint64(seed), 0))
		n := 1 + rng.IntN(20)
		hdrs := make([]tar.Header, 0, n)
		contents := map[string][]byte{}
		for i := range n {
			tf := typeflags[rng.IntN(len(typeflags))]
			format := formats[rng.IntN(len(formats))]
			// USTAR and GNU cannot carry wide ids, sub-second times, or long
			// names; only PAX (or unspecified, which upgrades to PAX) can.
			pax := format == tar.FormatPAX || format == tar.FormatUnknown
			name := fmt.Sprintf("d%d/f%d", rng.IntN(3), i)
			if pax && rng.IntN(8) == 0 {
				name += strings.Repeat("x", 120) // forces a PAX path record
			}
			idMax, nanos := 1<<21, int64(0)
			if pax {
				idMax, nanos = 1<<32, int64(rng.IntN(1e9))
			}
			hdr := tar.Header{
				Typeflag: tf,
				Name:     name,
				Mode:     int64(rng.IntN(0o10000)),
				Uid:      rng.IntN(idMax),
				Gid:      rng.IntN(idMax),
				Uname:    names[rng.IntN(len(names))],
				Gname:    names[rng.IntN(len(names))],
				ModTime:  time.Unix(rng.Int64N(1<<33), nanos),
				Format:   format,
			}
			switch tf {
			case tar.TypeDir:
				hdr.Name += "/"
			case tar.TypeSymlink, tar.TypeLink:
				hdr.Linkname = fmt.Sprintf("target%d", rng.IntN(5))
			case tar.TypeChar, tar.TypeBlock:
				hdr.Devmajor, hdr.Devminor = rng.Int64N(256), rng.Int64N(1<<20)
			case tar.TypeReg:
				body := make([]byte, rng.IntN(64))
				hdr.Size = int64(len(body))
				contents[name] = body
			}
			if pax && rng.IntN(2) == 0 {
				hdr.PAXRecords = map[string]string{}
				switch rng.IntN(3) {
				case 0:
					var sum [20]byte
					for j := range sum {
						sum[j] = byte(rng.UintN(256))
					}
					hdr.PAXRecords[paxChecksumKey] = hex.EncodeToString(sum[:])
				case 1:
					hdr.PAXRecords[paxChecksumKey] = "Q1notreallyhex"
				}
				if rng.IntN(2) == 0 {
					hdr.PAXRecords["SCHILY.xattr.user.k"] = "v"
				}
				if rng.IntN(4) == 0 {
					hdr.PAXRecords["SCHILY.xattr.user.empty"] = ""
				}
			}
			hdrs = append(hdrs, hdr)
		}

		data := writeTar(t, hdrs, contents)
		want := readHeaders(t, data)
		fsys := newFS(t, data)
		entries := fsys.Entries()
		if len(entries) != len(want) {
			t.Fatalf("seed %d: %d entries, want %d", seed, len(entries), len(want))
		}
		for i, e := range entries {
			checkEntry(t, e, want[i])
		}
		if t.Failed() {
			t.Fatalf("seed %d failed", seed)
		}
	}
}
