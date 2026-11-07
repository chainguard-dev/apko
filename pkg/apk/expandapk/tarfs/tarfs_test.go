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
	"io"
	"io/fs"
	"testing"
)

// buildTar writes the given headers (each paired with body content) into a
// tar archive and returns the raw bytes, ready to back an FS via New.
func buildTar(t *testing.T, entries []struct {
	hdr  *tar.Header
	body string
}) []byte {
	t.Helper()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		if e.hdr.Size == 0 && e.body != "" {
			e.hdr.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(e.hdr); err != nil {
			t.Fatalf("WriteHeader(%q): %v", e.hdr.Name, err)
		}
		if e.body != "" {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatalf("Write(%q): %v", e.hdr.Name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar.Close: %v", err)
	}
	return buf.Bytes()
}

// TestEntry_Type_MatchesTypeBitsOnly is the issue #2495 regression: fs.DirEntry
// documents Type() as returning ONLY the type bits (the same value as
// Info().Mode().Type()), not the full mode. A regular file carrying
// permission bits (0644) must report Type() == 0.
func TestEntry_Type_MatchesTypeBitsOnly(t *testing.T) {
	raw := buildTar(t, []struct {
		hdr  *tar.Header
		body string
	}{
		{hdr: &tar.Header{Name: "usr/bin/hello", Typeflag: tar.TypeReg, Mode: 0o755}, body: "hello world\n"},
		{hdr: &tar.Header{Name: "usr/bin/", Typeflag: tar.TypeDir, Mode: 0o755}},
	})

	fsys, err := New(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	fi, err := fsys.Stat("usr/bin/hello")
	if err != nil {
		t.Fatalf("Stat(usr/bin/hello): %v", err)
	}

	ents, err := fsys.ReadDir("usr/bin")
	if err != nil {
		t.Fatalf("ReadDir(usr/bin): %v", err)
	}
	var got fs.DirEntry
	for _, e := range ents {
		if e.Name() == "hello" {
			got = e
		}
	}
	if got == nil {
		t.Fatalf("ReadDir(usr/bin) did not include hello: %v", ents)
	}

	want := fi.Mode().Type()
	if got.Type() != want {
		t.Errorf("DirEntry.Type() = %v (full mode %v), want only the type bits %v (fs.DirEntry contract: Type() must equal Info().Mode().Type())",
			got.Type(), fi.Mode(), want)
	}
}

// TestOpen_Hardlink is the issue #2494 regression: a tar.TypeLink's Linkname
// is archive-root-relative (per the tar format), not relative to the link's
// own directory, so it must be looked up directly rather than joined with
// e.dir.
func TestOpen_Hardlink(t *testing.T) {
	raw := buildTar(t, []struct {
		hdr  *tar.Header
		body string
	}{
		{hdr: &tar.Header{Name: "usr/bin/hello", Typeflag: tar.TypeReg, Mode: 0o755}, body: "hello world\n"},
		{hdr: &tar.Header{Name: "usr/bin/hard", Typeflag: tar.TypeLink, Linkname: "usr/bin/hello"}},
	})

	fsys, err := New(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	f, err := fsys.Open("usr/bin/hard")
	if err != nil {
		t.Fatalf("Open(usr/bin/hard): %v (hardlink target must resolve against the archive root, not the link's directory)", err)
	}
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("reading usr/bin/hard: %v", err)
	}
	if string(got) != "hello world\n" {
		t.Errorf("usr/bin/hard content = %q, want %q", got, "hello world\n")
	}
}

// TestOpen_AbsoluteSymlink is the other half of issue #2494: an absolute
// symlink target is looked up verbatim, but the fsys index is keyed by
// archive member names with no leading slash, so it must be stripped first.
func TestOpen_AbsoluteSymlink(t *testing.T) {
	raw := buildTar(t, []struct {
		hdr  *tar.Header
		body string
	}{
		{hdr: &tar.Header{Name: "usr/bin/hello", Typeflag: tar.TypeReg, Mode: 0o755}, body: "hello world\n"},
		{hdr: &tar.Header{Name: "usr/bin/abs", Typeflag: tar.TypeSymlink, Linkname: "/usr/bin/hello"}},
	})

	fsys, err := New(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	f, err := fsys.Open("usr/bin/abs")
	if err != nil {
		t.Fatalf("Open(usr/bin/abs): %v (absolute symlink target must resolve from the archive root)", err)
	}
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("reading usr/bin/abs: %v", err)
	}
	if string(got) != "hello world\n" {
		t.Errorf("usr/bin/abs content = %q, want %q", got, "hello world\n")
	}
}

// TestOpen_RelativeSymlink is a control: the one case the pre-fix code
// already handled correctly, kept green through the fix so a regression
// here would be caught immediately.
func TestOpen_RelativeSymlink(t *testing.T) {
	raw := buildTar(t, []struct {
		hdr  *tar.Header
		body string
	}{
		{hdr: &tar.Header{Name: "usr/bin/hello", Typeflag: tar.TypeReg, Mode: 0o755}, body: "hello world\n"},
		{hdr: &tar.Header{Name: "usr/bin/rel", Typeflag: tar.TypeSymlink, Linkname: "hello"}},
	})

	fsys, err := New(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	f, err := fsys.Open("usr/bin/rel")
	if err != nil {
		t.Fatalf("Open(usr/bin/rel): %v", err)
	}
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("reading usr/bin/rel: %v", err)
	}
	if string(got) != "hello world\n" {
		t.Errorf("usr/bin/rel content = %q, want %q", got, "hello world\n")
	}
}
