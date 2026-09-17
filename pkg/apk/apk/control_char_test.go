package apk

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"chainguard.dev/apko/pkg/apk/expandapk/tarfs"
	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/apk/types"
)

// newTestAPKInDir returns an APK backed by a fresh dirFS under a temp dir.
func newTestAPKInDir(t *testing.T) *APK {
	t.Helper()
	base := filepath.Join(t.TempDir(), "base")
	fsys := apkfs.DirFS(t.Context(), base, apkfs.WithCreateDir())
	if fsys == nil {
		t.Fatalf("failed to create dirfs for base %s", base)
	}
	a, err := New(t.Context(), WithFS(fsys))
	if err != nil {
		t.Fatalf("apk.New: %v", err)
	}
	return a
}

// recordingWriteHeaderer is a WriteHeaderer that records the entry names it is
// asked to write, so a test can assert that a rejected entry never reached it.
type recordingWriteHeaderer struct{ written []string }

func (w *recordingWriteHeaderer) WriteHeader(hdr tar.Header, _ fs.FS, _ *Package) (bool, error) {
	w.written = append(w.written, hdr.Name)
	return true, nil
}

// tarWith builds a tar stream from the given headers, writing one byte of
// content for each regular-file entry. Unlike makeTestTarWithRegFile it does not
// synthesise parent directories, so a test can control the entry set exactly --
// which is what lets these tables put a control character in a directory
// component rather than only in the leaf.
func tarWith(t *testing.T, headers ...tar.Header) *bytes.Reader {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for i := range headers {
		h := headers[i]
		if h.Typeflag == tar.TypeReg && h.Size == 0 {
			h.Size = 1
		}
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatalf("WriteHeader(%q): %v", h.Name, err)
		}
		if h.Typeflag == tar.TypeReg {
			if _, err := tw.Write(bytes.Repeat([]byte("x"), int(h.Size))); err != nil {
				t.Fatalf("Write(%q): %v", h.Name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	return bytes.NewReader(buf.Bytes())
}

// lazyArgs adapts a tarfs.FS to lazilyInstallAPKFiles' parameters, which upstream
// changed to take the entry list and the backing fs.FS separately rather than the
// tarfs.FS itself.
func lazyArgs(tf *tarfs.FS) ([]tar.Header, fs.FS) {
	entries := tf.Entries()
	headers := make([]tar.Header, 0, len(entries))
	for _, e := range entries {
		headers = append(headers, e.Header)
	}
	return headers, tf
}

// A control character in an archive entry name lets a package inject arbitrary
// lines into the apk installed database, because AddInstalledPackage writes
// F:/R: lines from tar.Header.Name verbatim. A newline can terminate the
// current record and forge a whole new package entry, which then propagates
// into the generated SBOM.
//
// apk-tools rejects these at install time: see contains_control_character() in
// src/database.c, added in c1594f60 "db: consider control characters in
// filename as malicious".
func TestInstallRejectsControlCharactersInEntryName(t *testing.T) {
	cases := []struct {
		name string
		file string
	}{
		{
			name: "newline forging a whole package record",
			file: "usr/readme.txt\n\nP:totally-not-malware\nV:9.9.9\nA:x86_64\nL:MIT",
		},
		{name: "bare newline", file: "usr/read\nme.txt"},
		{name: "carriage return", file: "usr/read\rme.txt"},
		{name: "tab", file: "usr/read\tme.txt"},
		// NUL is deliberately absent: archive/tar refuses to encode it into a
		// header name, and the reader cannot surface one either (USTAR name
		// fields are NUL-terminated, GNU long names truncate at the first NUL,
		// and validPAXRecord rejects NUL in "path"). It is covered directly in
		// TestContainsControlCharacterAllBytes instead.
		{name: "bell (0x07)", file: "usr/read\ame.txt"},
		{name: "escape (0x1b)", file: "usr/read\x1bme.txt"},
		{name: "unit separator (0x1f, highest rejected)", file: "usr/read\x1fme.txt"},
		{name: "DEL (0x7f)", file: "usr/read\x7fme.txt"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newTestAPKInDir(t)

			r, err := makeTestTarWithRegFile(tc.file, []byte("hello"), 0o644)
			if err != nil {
				t.Fatalf("makeTestTarWithRegFile(%q): %v", tc.file, err)
			}

			_, err = a.installAPKFiles(t.Context(), r, &Package{Name: "innocent", Version: "1.0"})
			if err == nil {
				t.Fatalf("installAPKFiles(%q) = nil error, want rejection", tc.file)
			}
			if _, ok := errors.AsType[InvalidEntryNameError](err); !ok {
				t.Errorf("installAPKFiles(%q) error = %v (%T), want an InvalidEntryNameError", tc.file, err, err)
			}

			// Rejecting is only half the property: the entry must never have
			// been written. Without this, moving the guard to the bottom of the
			// loop keeps every other assertion green while the file lands on
			// disk. TestPathTraversal asserts the same thing for its own class.
			if _, statErr := a.fs.Stat(tc.file); statErr == nil {
				t.Errorf("installAPKFiles(%q) rejected the package but the entry exists on disk; want it never written", tc.file)
			}
			if owner, ok := a.installedFiles[tc.file]; ok {
				t.Errorf("installAPKFiles(%q) rejected the package but installedFiles records it as owned by %q", tc.file, owner.Name)
			}
		})
	}
}

// Every row above puts the offending byte in a regular file's leaf name. These
// exercise the other entry types and positions: directory names become F: lines,
// which are an independent forging sink from R:, and R: only ever receives
// filepath.Base -- so a control character in a non-leaf component is reachable
// only through its companion F: entry.
func TestInstallRejectsControlCharactersByEntryType(t *testing.T) {
	cases := []struct {
		name    string
		headers []tar.Header
	}{
		{
			name:    "directory entry name",
			headers: []tar.Header{{Name: "usr/ev\nil/", Typeflag: tar.TypeDir, Mode: 0o755}},
		},
		{
			name:    "symlink entry name",
			headers: []tar.Header{{Name: "usr/ev\nil", Linkname: "target", Typeflag: tar.TypeSymlink, Mode: 0o777}},
		},
		{
			name: "hardlink entry name",
			headers: []tar.Header{
				{Name: "legit", Typeflag: tar.TypeReg, Mode: 0o644},
				{Name: "ev\nil", Linkname: "legit", Typeflag: tar.TypeLink, Mode: 0o644},
			},
		},
		{
			// Hidden control-section entries hit the startedDataSection skip.
			// The guard must precede that skip; if it were moved below, this
			// name would be silently accepted.
			name:    "hidden control-section entry, before the data section starts",
			headers: []tar.Header{{Name: ".PKGIN\nFO", Typeflag: tar.TypeReg, Mode: 0o644}},
		},
		{
			name: "long name forcing the PAX path",
			headers: []tar.Header{
				{Name: "usr/share/" + strings.Repeat("a", 120) + "\nP:forged", Typeflag: tar.TypeReg, Mode: 0o644},
			},
		},
		{
			name:    "empty entry name",
			headers: []tar.Header{{Name: "", Typeflag: tar.TypeReg, Mode: 0o644}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newTestAPKInDir(t)
			r := tarWith(t, tc.headers...)

			_, err := a.installAPKFiles(t.Context(), r, &Package{Name: "innocent", Version: "1.0"})
			if err == nil {
				t.Fatalf("installAPKFiles(%s) = nil error, want rejection", tc.name)
			}
			if _, ok := errors.AsType[InvalidEntryNameError](err); !ok {
				t.Errorf("installAPKFiles(%s) error = %v (%T), want an InvalidEntryNameError", tc.name, err, err)
			}
		})
	}
}

// installPackage picks lazilyInstallAPKFiles over installAPKFiles whenever the
// backing filesystem implements WriteHeaderer -- the normal apko configuration --
// so guarding only installAPKFiles would leave the path that actually runs in
// production exploitable.
func TestLazyInstallRejectsControlCharactersInEntryName(t *testing.T) {
	cases := []struct {
		name    string
		headers []tar.Header
	}{
		{
			name: "newline forging a package record, offending entry last",
			headers: []tar.Header{
				{Name: "usr/", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "usr/readme.txt\n\nP:totally-not-malware\nV:9.9.9", Typeflag: tar.TypeReg, Mode: 0o644},
			},
		},
		{
			name: "offending entry first, good entries after",
			headers: []tar.Header{
				{Name: "usr/ev\nil.txt", Typeflag: tar.TypeReg, Mode: 0o644},
				{Name: "usr/", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "usr/innocent.txt", Typeflag: tar.TypeReg, Mode: 0o644},
			},
		},
		{
			name:    "empty entry name",
			headers: []tar.Header{{Name: "", Typeflag: tar.TypeReg, Mode: 0o644}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newTestAPKInDir(t)
			r := tarWith(t, tc.headers...)
			tf, err := tarfs.New(r, r.Size())
			if err != nil {
				t.Fatalf("tarfs.New: %v", err)
			}

			wh := &recordingWriteHeaderer{}
			lazyEntries, lazySrc := lazyArgs(tf)
			_, err = a.lazilyInstallAPKFiles(t.Context(), wh, lazyEntries, lazySrc, &Package{Name: "innocent", Version: "1.0"})
			if err == nil {
				t.Fatalf("lazilyInstallAPKFiles(%s) = nil error, want rejection", tc.name)
			}
			if _, ok := errors.AsType[InvalidEntryNameError](err); !ok {
				t.Errorf("error = %v (%T), want an InvalidEntryNameError", err, err)
			}

			// The lazy path validates every entry up front, so nothing at all
			// should have been written -- not even the entries preceding the
			// offending one. Asserting the count directly, rather than
			// re-running containsControlCharacter over what was written, keeps
			// the system under test out of its own oracle.
			if len(wh.written) != 0 {
				t.Errorf("WriteHeader received %q, want nothing written before rejection", wh.written)
			}
		})
	}
}

// The rejection above must not cost us legitimate names. A validator that is
// too eager is its own outage: UTF-8 file names are ordinary in real packages,
// and upstream's first attempt at this check rejected every one of them.
func TestInstallAcceptsLegitimateEntryNames(t *testing.T) {
	cases := []struct {
		name string
		file string
	}{
		{name: "plain ascii", file: "usr/readme.txt"},
		{name: "nested path", file: "usr/share/doc/foo/README"},
		{name: "spaces in name", file: "usr/share/my documents.txt"},
		{name: "tilde, just below DEL", file: "usr/share/backup~"},
		{name: "latin-1 supplement UTF-8", file: "usr/share/café.txt"},
		{name: "CJK UTF-8", file: "usr/share/日本語.txt"},
		{name: "emoji UTF-8", file: "usr/share/🔒.txt"},
		{name: "shell metacharacters", file: "usr/share/weird$name;&|.txt"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newTestAPKInDir(t)

			r, err := makeTestTarWithRegFile(tc.file, []byte("hello"), 0o644)
			if err != nil {
				t.Fatalf("makeTestTarWithRegFile(%q): %v", tc.file, err)
			}

			got, err := a.installAPKFiles(t.Context(), r, &Package{Name: "legit", Version: "1.0"})
			if err != nil {
				t.Fatalf("installAPKFiles(%q) = %v, want success", tc.file, err)
			}

			if !slices.ContainsFunc(got, func(h tar.Header) bool { return h.Name == tc.file }) {
				names := make([]string, 0, len(got))
				for _, h := range got {
					names = append(names, h.Name)
				}
				t.Errorf("installAPKFiles(%q) did not report the entry as installed; got %v", tc.file, names)
			}

			if _, err := a.fs.Stat(tc.file); err != nil {
				t.Errorf("stat(%q) after install: %v, want the file to exist", tc.file, err)
			}
		})
	}
}

// Same positive coverage for the fast path. Without this, mutating the lazy
// guard to reject everything leaves the whole pkg/apk/apk suite green.
func TestLazyInstallAcceptsLegitimateEntryNames(t *testing.T) {
	for _, name := range []string{
		"usr/readme.txt",
		"usr/share/café.txt",
		"usr/share/日本語.txt",
		"usr/share/🔒.txt",
		"usr/share/my documents.txt",
	} {
		t.Run(name, func(t *testing.T) {
			a := newTestAPKInDir(t)

			r, err := makeTestTarWithRegFile(name, []byte("hello"), 0o644)
			if err != nil {
				t.Fatalf("makeTestTarWithRegFile(%q): %v", name, err)
			}
			tf, err := tarfs.New(r, r.Size())
			if err != nil {
				t.Fatalf("tarfs.New: %v", err)
			}

			wh := &recordingWriteHeaderer{}
			lazyEntries, lazySrc := lazyArgs(tf)
			got, err := a.lazilyInstallAPKFiles(t.Context(), wh, lazyEntries, lazySrc, &Package{Name: "legit", Version: "1.0"})
			if err != nil {
				t.Fatalf("lazilyInstallAPKFiles(%q) = %v, want success", name, err)
			}
			if !slices.ContainsFunc(got, func(h tar.Header) bool { return h.Name == name }) {
				t.Errorf("lazilyInstallAPKFiles(%q) did not report the entry; written=%q returned=%v", name, wh.written, got)
			}
		})
	}
}

// AddInstalledPackage is exported and is the actual injection sink: it writes
// F:/R: lines from tar.Header.Name verbatim. Guarding only the install paths
// would leave the sink open to any other caller, and pkg/apk/apk is consumed
// downstream by melange. This is the direct regression test for the entry-name
// half of GHSA-389p-892w-qwgf.
//
// The sink refuses a narrower byte class than the install paths do -- only the
// bytes that break the record format. See
// TestAddInstalledPackageAcceptsBytesTheInstallPathsRefuse for the other half of
// that contract, and validateRecordedEntryName for why the two differ.
func TestAddInstalledPackageRejectsRecordBreakingEntryNames(t *testing.T) {
	const forge = "\n\nP:totally-not-malware\nV:9.9.9\nA:x86_64\nL:MIT"
	cases := []struct {
		name  string
		files []tar.Header
	}{
		{
			name: "regular file name, forged record appended",
			files: []tar.Header{
				{Name: "usr", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "usr/readme.txt" + forge, Typeflag: tar.TypeReg, Size: 10, Mode: 0o644},
			},
		},
		{
			name: "directory name, forged record via the F: line",
			files: []tar.Header{
				{Name: "usr", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "usr/share" + forge, Typeflag: tar.TypeDir, Mode: 0o755},
			},
		},
		{
			name: "symlink name",
			files: []tar.Header{
				{Name: "usr", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "usr/link" + forge, Linkname: "target", Typeflag: tar.TypeSymlink, Mode: 0o777},
			},
		},
		{
			// R: receives only filepath.Base, so this byte reaches the database
			// through the companion F: line rather than the R: line.
			name: "control char only in a directory component, clean basename",
			files: []tar.Header{
				{Name: "usr", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "usr/ev\nil/readme.txt", Typeflag: tar.TypeReg, Size: 1, Mode: 0o644},
			},
		},
		{
			// Offending entry first: pins that the guard scans the whole slice
			// rather than only its tail.
			name: "offending entry first, good entries after",
			files: []tar.Header{
				{Name: "usr/ev" + forge, Typeflag: tar.TypeReg, Size: 1, Mode: 0o644},
				{Name: "usr", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "usr/innocent.txt", Typeflag: tar.TypeReg, Size: 1, Mode: 0o644},
			},
		},
		{
			name:  "name is nothing but a newline",
			files: []tar.Header{{Name: "\n", Typeflag: tar.TypeReg, Size: 1, Mode: 0o644}},
		},
		{
			// A bare CR cannot forge a record, but bufio.ScanLines eats it on
			// read-back, so the value would not survive the round trip.
			name:  "trailing carriage return",
			files: []tar.Header{{Name: "usr/readme.txt\r", Typeflag: tar.TypeReg, Size: 1, Mode: 0o644}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, _, err := testGetTestAPK()
			if err != nil {
				t.Fatalf("testGetTestAPK: %v", err)
			}
			before, err := a.GetInstalled()
			if err != nil {
				t.Fatalf("GetInstalled: %v", err)
			}

			_, err = a.AddInstalledPackage(&Package{Name: "innocent", Version: "1.0", Arch: "x86_64"}, tc.files)
			if err == nil {
				t.Fatalf("AddInstalledPackage(%s) = nil error, want rejection", tc.name)
			}
			if _, ok := errors.AsType[InvalidEntryNameError](err); !ok {
				t.Errorf("AddInstalledPackage(%s) error = %v (%T), want an InvalidEntryNameError", tc.name, err, err)
			}

			after, err := a.GetInstalled()
			if err != nil {
				t.Fatalf("GetInstalled after rejection: %v", err)
			}
			if len(after) != len(before) {
				names := make([]string, 0, len(after))
				for _, p := range after {
					names = append(names, p.Name)
				}
				t.Errorf("%s: installed package count went %d -> %d after a rejected write; db was mutated. packages=%v",
					tc.name, len(before), len(after), names)
			}
			for _, p := range after {
				if p.Name == "totally-not-malware" {
					t.Errorf("%s: forged package %q present in installed db", tc.name, p.Name)
				}
			}
		})
	}
}

// The other half of the sink's contract: bytes that the install paths refuse
// outright must still be written through here, unchanged.
//
// pkg/build feeds every package of a user-supplied base image back through
// AddInstalledPackage, having read it out of that image's own database with
// ParseInstalled. Those names are not attacker-controlled in the way an archive's
// are -- they are already in the image -- so applying the strict install-path
// check here would fail the build over a byte that has been sitting harmlessly
// in a third-party base image for years, with no flag or allowlist to get past
// it. Dropping the entry instead would be worse: it would hide a file that is
// really present, which is the concealment this package exists to prevent.
//
// So each row below must be accepted AND survive the round trip byte-for-byte.
// A future tightening of validateRecordedEntryName that reintroduces the strict
// class here will fail this test, which is the point: the difference between the
// two checks is deliberate, not an oversight.
func TestAddInstalledPackageAcceptsBytesTheInstallPathsRefuse(t *testing.T) {
	cases := []struct {
		name string
		// entry is the file name to record, relative to the "usr" directory
		// created alongside it.
		entry string
	}{
		{"tab", "usr/foo\tbar"},
		{"DEL", "usr/foo\x7fbar"},
		{"bell", "usr/foo\abar"},
		{"escape", "usr/foo\x1bbar"},
		{"NUL", "usr/foo\x00bar"},
		{"unit separator", "usr/foo\x1fbar"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The strict check must reject it, or the row is not testing the
			// asymmetry it claims to.
			if err := validateEntryName("pkg", tc.entry); err == nil {
				t.Fatalf("validateEntryName(%q) = nil; this row no longer covers a byte "+
					"the install paths refuse, so it cannot demonstrate the asymmetry", tc.entry)
			}

			a, _, err := testGetTestAPK()
			if err != nil {
				t.Fatalf("testGetTestAPK: %v", err)
			}
			before, err := a.GetInstalled()
			if err != nil {
				t.Fatalf("GetInstalled: %v", err)
			}

			files := []tar.Header{
				{Name: "usr", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: tc.entry, Typeflag: tar.TypeReg, Size: 1, Mode: 0o644},
			}
			if _, err := a.AddInstalledPackage(&Package{Name: "based", Version: "1.0", Arch: "x86_64"}, files); err != nil {
				t.Fatalf("AddInstalledPackage(%q) = %v, want it accepted at this sink", tc.entry, err)
			}

			after, err := a.GetInstalled()
			if err != nil {
				t.Fatalf("GetInstalled after add: %v; the database was left unparseable", err)
			}
			if len(after) != len(before)+1 {
				t.Fatalf("installed count = %d, want %d", len(after), len(before)+1)
			}

			// Byte-for-byte: accepting the entry is only useful if the name is
			// still the one the base image had.
			added := after[len(after)-1]
			if !slices.ContainsFunc(added.Files, func(h tar.Header) bool { return h.Name == tc.entry }) {
				got := make([]string, 0, len(added.Files))
				for _, h := range added.Files {
					got = append(got, h.Name)
				}
				t.Errorf("entry %q did not round-trip; recorded files = %q", tc.entry, got)
			}
		})
	}
}

// A legitimate package must still round-trip through the installed database
// unchanged: written by AddInstalledPackage, read back by GetInstalled.
func TestAddInstalledPackageRoundTripsLegitimateNames(t *testing.T) {
	a, _, err := testGetTestAPK()
	if err != nil {
		t.Fatalf("testGetTestAPK: %v", err)
	}

	before, err := a.GetInstalled()
	if err != nil {
		t.Fatalf("GetInstalled: %v", err)
	}

	wantFiles := []string{
		"usr/share/café.txt",
		"usr/share/日本語.txt",
		"usr/share/my documents.txt",
	}
	files := make([]tar.Header, 0, 2+len(wantFiles))
	files = append(files,
		tar.Header{Name: "usr", Typeflag: tar.TypeDir, Mode: 0o755},
		tar.Header{Name: "usr/share", Typeflag: tar.TypeDir, Mode: 0o755},
	)
	for _, f := range wantFiles {
		files = append(files, tar.Header{Name: f, Typeflag: tar.TypeReg, Size: 5, Mode: 0o644})
	}

	pkg := &Package{
		Name: "legit", Version: "2.0", Arch: "x86_64",
		Description: "an ordinary package with a tab\there and UTF-8 café",
	}
	if _, err := a.AddInstalledPackage(pkg, files); err != nil {
		t.Fatalf("AddInstalledPackage with legitimate UTF-8 names = %v, want success", err)
	}

	after, err := a.GetInstalled()
	if err != nil {
		t.Fatalf("GetInstalled after add: %v", err)
	}
	if len(after) != len(before)+1 {
		t.Fatalf("installed package count = %d, want %d", len(after), len(before)+1)
	}

	idx := slices.IndexFunc(after, func(p *InstalledPackage) bool { return p.Name == "legit" })
	if idx < 0 {
		t.Fatalf("package %q not found in installed db after add", "legit")
	}
	added := after[idx]
	if added.Version != "2.0" {
		t.Errorf("added package version = %q, want %q", added.Version, "2.0")
	}
	if added.Description != pkg.Description {
		t.Errorf("Description round trip = %q, want %q", added.Description, pkg.Description)
	}

	recorded := make(map[string]bool, len(added.Files))
	for _, f := range added.Files {
		recorded[f.Name] = true
	}
	for _, want := range wantFiles {
		if !recorded[want] {
			got := make([]string, 0, len(added.Files))
			for _, f := range added.Files {
				got = append(got, f.Name)
			}
			t.Errorf("file %q missing from installed db after round trip; got %v", want, got)
		}
	}
}

// Exhaustive boundary proof for the byte predicate, complementing the named
// rows below: 0x00-0x1f and 0x7f reject, everything else accepts, in every
// position within a name.
func TestContainsControlCharacterAllBytes(t *testing.T) {
	for i := range 256 {
		b := byte(i)
		want := b < 0x20 || b == 0x7f
		t.Run(fmt.Sprintf("byte_0x%02x", b), func(t *testing.T) {
			for _, in := range []string{
				string([]byte{b}),
				"read" + string([]byte{b}) + "me",
				string([]byte{b}) + "readme",
				"readme" + string([]byte{b}),
			} {
				if got := containsControlCharacter(in); got != want {
					t.Errorf("containsControlCharacter(%q) = %v, want %v (byte 0x%02x)", in, got, want, b)
				}
			}
		})
	}
}

// Every single-byte case is already covered exhaustively by
// TestContainsControlCharacterAllBytes above, in four positions each. What it
// cannot cover is a multi-byte UTF-8 sequence, where the question is whether the
// continuation bytes are misread -- apk-tools' first attempt compared a signed
// char, so every byte >= 0x80 read as negative and all of these were wrongly
// rejected (fixed upstream in ab7b8e3, alpine issue #10737). These rows fail if
// the Go port regresses to a signed comparison.
func TestContainsControlCharacterMultiByteUTF8(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"latin-1 supplement", "café.txt", false},
		{"CJK", "日本語.txt", false},
		{"emoji", "🔒.txt", false},
		{"realistic path", "usr/lib/libfoo.so.1", false},

		// A control byte adjacent to a multi-byte sequence must still be found:
		// a decode-based implementation that skipped continuation bytes could
		// otherwise step over it.
		{"newline after a multi-byte rune", "café\nme", true},
		{"newline between two multi-byte runes", "日\n語", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := containsControlCharacter(tc.in); got != tc.want {
				t.Errorf("containsControlCharacter(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// validateEntryName layers the empty-name check on top of the predicate. The
// empty case matters because containsControlCharacter("") is correctly false,
// which previously let an empty name reach an unguarded header.Name[0] index.
func TestValidateEntryName(t *testing.T) {
	cases := []struct {
		name  string
		entry string
		want  error // nil means the name must be accepted
	}{
		{name: "ordinary name", entry: "usr/readme.txt"},
		{name: "UTF-8 name", entry: "usr/café.txt"},
		{name: "empty name", entry: "", want: ErrEmptyName},
		{name: "newline", entry: "usr/ev\nil", want: ErrControlCharacter},
		{name: "DEL", entry: "usr/ev\x7fil", want: ErrControlCharacter},
		{name: "NUL", entry: "usr/ev\x00il", want: ErrControlCharacter},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateEntryName("somepkg", tc.entry)
			if (tc.want == nil) != (err == nil) {
				t.Fatalf("validateEntryName(%q) error = %v, want %v", tc.entry, err, tc.want)
			}
			if tc.want == nil {
				return
			}

			// The reason must be matchable programmatically. Before sentinels
			// it was free-text prose, so the only way to tell "empty" from
			// "control character" apart was to parse the message.
			if !errors.Is(err, tc.want) {
				t.Errorf("errors.Is(err, %v) = false; err = %v", tc.want, err)
			}
			// ...and the two reasons must not be confusable with each other.
			// (Comparing the sentinels with != is deliberate here: these are the
			// canonical values, not wrapped errors, and the point is to pick out
			// the one that is NOT the expected reason.)
			for _, other := range []error{ErrEmptyName, ErrControlCharacter} {
				if !errors.Is(other, tc.want) && errors.Is(err, other) {
					t.Errorf("errors.Is(err, %v) = true, but the reason was %v", other, tc.want)
				}
			}

			var got InvalidEntryNameError
			if !errors.As(err, &got) {
				t.Fatalf("error = %v (%T), want InvalidEntryNameError", err, err)
			}
			if got.Package != "somepkg" || got.Path != tc.entry {
				t.Errorf("error = %+v, want Package=%q Path=%q", got, "somepkg", tc.entry)
			}
		})
	}
}

// Two distinct rejections must not compare equal. The previous hand-written
// Is() method matched on type alone, so errors.Is reported a match between any
// two InvalidEntryNameErrors -- meaning errors.Is(err, theOneIJustSaw) was
// unconditionally true, which inverts what errors.Is is supposed to mean.
func TestInvalidEntryNameErrorMatching(t *testing.T) {
	empty := validateEntryName("pkg-a", "")
	ctrl := validateEntryName("pkg-b", "usr/ev\nil")

	if errors.Is(empty, ctrl) {
		t.Errorf("errors.Is reports a match between two unrelated rejections:\n  %v\n  %v", empty, ctrl)
	}
	if !errors.Is(empty, ErrEmptyName) {
		t.Errorf("errors.Is(empty, ErrEmptyName) = false; err = %v", empty)
	}
	if !errors.Is(ctrl, ErrControlCharacter) {
		t.Errorf("errors.Is(ctrl, ErrControlCharacter) = false; err = %v", ctrl)
	}

	// Both must survive wrapping, which is how callers actually see them.
	wrapped := fmt.Errorf("installing package: %w", ctrl)
	if !errors.Is(wrapped, ErrControlCharacter) {
		t.Errorf("errors.Is on a wrapped error = false; err = %v", wrapped)
	}
	var as InvalidEntryNameError
	if !errors.As(wrapped, &as) || as.Path != "usr/ev\nil" {
		t.Errorf("errors.As on a wrapped error = %+v, want Path=%q", as, "usr/ev\nil")
	}
	if errors.Is(ctrl, FileConflictError{}) {
		t.Error("errors.Is matched an unrelated error type")
	}
}

func BenchmarkContainsControlCharacter(b *testing.B) {
	s := "usr/share/doc/some-package/README.md"
	b.ReportAllocs()
	var sink bool
	for b.Loop() {
		sink = containsControlCharacter(s)
	}
	_ = sink
}

// The two entry-name reasons must be distinguishable in both directions.
// TestValidateEntryName's own loop cannot detect them being aliased: its guard
// skips the expected sentinel, and under aliasing both sentinels are expected,
// so the body never runs.
func TestEntryNameSentinelsAreDistinct(t *testing.T) {
	if errors.Is(ErrEmptyName, ErrControlCharacter) || errors.Is(ErrControlCharacter, ErrEmptyName) {
		t.Fatal("ErrEmptyName and ErrControlCharacter are the same value; a caller cannot " +
			"tell an empty name from a control character")
	}

	empty := validateEntryName("pkg", "")
	ctrl := validateEntryName("pkg", "usr/ev\nil")
	if errors.Is(empty, ErrControlCharacter) {
		t.Errorf("empty-name rejection matches ErrControlCharacter: %v", empty)
	}
	if errors.Is(ctrl, ErrEmptyName) {
		t.Errorf("control-character rejection matches ErrEmptyName: %v", ctrl)
	}
}

// The .PKGINFO layer and the database sink reject the same class of value, one
// layer apart. A caller must be able to match both with a single errors.Is
// target: two look-alike sentinels would mean anyone matching one silently
// misses the other, which is the prose coupling these sentinels exist to
// remove rather than to reintroduce across a package boundary.
func TestEmbeddedNewlineSentinelIsSharedWithTypes(t *testing.T) {
	if !errors.Is(ErrEmbeddedNewline, types.ErrEmbeddedNewline) {
		t.Fatalf("apk.ErrEmbeddedNewline (%v) and types.ErrEmbeddedNewline (%v) are distinct "+
			"values; a caller matching one misses the other", ErrEmbeddedNewline, types.ErrEmbeddedNewline)
	}

	// A .PKGINFO-layer rejection must match the apk-layer sentinel...
	_, parseErr := types.ParsePackageInfo(strings.NewReader(
		"pkgname = innocent\npkgver = 1.0\npkgdesc = \"\"\"a\nP:forged\"\"\"\n"))
	if parseErr == nil {
		t.Fatal("setup: ParsePackageInfo accepted a multi-line value")
	}
	if !errors.Is(parseErr, ErrEmbeddedNewline) {
		t.Errorf("errors.Is(ParsePackageInfo error, apk.ErrEmbeddedNewline) = false; err = %v", parseErr)
	}

	// ...and a sink rejection must match the types-layer sentinel.
	a, _, err := testGetTestAPK()
	if err != nil {
		t.Fatalf("testGetTestAPK: %v", err)
	}
	_, sinkErr := a.AddInstalledPackage(
		&Package{Name: "innocent", Version: "1.0\n\nP:forged"},
		[]tar.Header{{Name: "usr", Typeflag: tar.TypeDir, Mode: 0o755}})
	if sinkErr == nil {
		t.Fatal("setup: AddInstalledPackage accepted a forging version")
	}
	if !errors.Is(sinkErr, types.ErrEmbeddedNewline) {
		t.Errorf("errors.Is(AddInstalledPackage error, types.ErrEmbeddedNewline) = false; err = %v", sinkErr)
	}

	// The other reasons must stay distinguishable from it.
	if errors.Is(sinkErr, ErrEmptyName) || errors.Is(sinkErr, ErrControlCharacter) {
		t.Errorf("the embedded-newline rejection also matches an unrelated reason: %v", sinkErr)
	}
}

// The control section is as attacker-controlled as the data section, and
// updateScriptsTar splices its entry names into names written to
// usr/lib/apk/db/scripts.tar in the produced image, which apk-tools in the
// running container reads and dispatches on by suffix. The install paths guard
// the data section; this covers the sibling sink.
//
// The rejection also has to happen before anything is written, because
// installPackage calls updateScriptsTar after the package's data files are
// already installed and recorded in a.installedFiles.
func TestUpdateScriptsTarRejectsControlCharactersInEntryNames(t *testing.T) {
	cases := []struct {
		name       string
		entry      string
		wantReject bool
	}{
		{name: "ordinary script", entry: ".post-install"},
		{name: "newline before the suffix", entry: "\n.post-install", wantReject: true},
		{name: "newline after the suffix", entry: ".post-install\nx", wantReject: true},
		{name: "DEL in the name", entry: ".pre-install\x7f", wantReject: true},
		{name: "tab in the name", entry: ".pre-install\tx", wantReject: true},
		// NUL is absent for the same reason as in the install-path table above:
		// a tar reader cannot surface one in a header name.
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, _, err := testGetTestAPK()
			if err != nil {
				t.Fatalf("testGetTestAPK: %v", err)
			}
			pkg := &Package{Name: "testpkg", Version: "1.0.0", Checksum: []byte("0123456789abcdef")}

			const body = "echo hi"
			var buf bytes.Buffer
			tw := tar.NewWriter(&buf)
			if err := tw.WriteHeader(&tar.Header{Name: tc.entry, Mode: 0o755, Size: int64(len(body))}); err != nil {
				t.Fatalf("WriteHeader(%q): %v", tc.entry, err)
			}
			if _, err := tw.Write([]byte(body)); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if err := tw.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			err = a.updateScriptsTar(pkg, bytes.NewReader(buf.Bytes()), nil)

			if !tc.wantReject {
				if err != nil {
					t.Fatalf("updateScriptsTar(%q) = %v, want acceptance", tc.entry, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("updateScriptsTar(%q) = nil error, want rejection", tc.entry)
			}
			if _, ok := errors.AsType[InvalidEntryNameError](err); !ok {
				t.Errorf("error = %v (%T), want an InvalidEntryNameError so a caller can "+
					"report this as a package problem", err, err)
			}

			// The offending name must not have reached the image's scripts.tar.
			scriptsTar, err := a.readScriptsTar()
			if err != nil {
				t.Fatalf("readScriptsTar: %v", err)
			}
			defer scriptsTar.Close()
			tr := tar.NewReader(scriptsTar)
			for {
				h, err := tr.Next()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					break
				}
				if strings.Contains(h.Name, tc.entry) {
					t.Errorf("rejected entry %q was still written to scripts.tar as %q", tc.entry, h.Name)
				}
			}
		})
	}
}

// installAPKFiles streams the archive, so it cannot pre-validate the way
// lazilyInstallAPKFiles does: by the time a bad entry is found, the entries
// before it are on disk and claimed in a.installedFiles. Those writes cannot be
// safely unwound -- some of the directories were already there -- so the APK
// instance is left describing a package that was never installed.
//
// Continuing to use it is what turns that into corruption. The stale ownership
// records are consulted by installRegularFile's conflict branch and by the
// slices.DeleteFunc owner filter that builds each package's record, so a later
// package shipping one of the same paths can have its R: line dropped: the file
// is physically present but appears in no package's record and therefore in no
// SBOM. That is this package's own concealment failure mode, reached through
// error handling rather than through a control character.
//
// InvalidEntryNameError exists so a consumer can report a malformed package
// rather than fail opaquely, which invites exactly that continuation. So the
// instance refuses further installs instead: a caller that carries on gets a
// loud error naming the original failure, not a quietly wrong image.
func TestInstallFailureMakesTheInstanceRefuseFurtherInstalls(t *testing.T) {
	const shared = "usr/share/common.txt"

	// Both install paths must poison the instance. lazilyInstallAPKFiles
	// pre-validates and so writes nothing, but a caller cannot know which path
	// ran, and its other error returns are not all pre-write either.
	for _, path := range []string{"streaming", "lazy"} {
		t.Run(path, func(t *testing.T) {
			a := newTestAPKInDir(t)
			rejected := &Package{Name: "rejected", Version: "1.0"}

			headers := []tar.Header{
				{Name: "usr", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "usr/share", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: shared, Typeflag: tar.TypeReg, Mode: 0o644},
				{Name: "usr/share/ev\nil.txt", Typeflag: tar.TypeReg, Mode: 0o644},
			}

			var firstErr error
			switch path {
			case "streaming":
				_, firstErr = a.installAPKFiles(t.Context(), tarWith(t, headers...), rejected)
			case "lazy":
				r := tarWith(t, headers...)
				tf, err := tarfs.New(r, r.Size())
				if err != nil {
					t.Fatalf("tarfs.New: %v", err)
				}
				lazyEntries, lazySrc := lazyArgs(tf)
				_, firstErr = a.lazilyInstallAPKFiles(t.Context(), &recordingWriteHeaderer{}, lazyEntries, lazySrc, rejected)
			}
			if firstErr == nil {
				t.Fatalf("%s install = nil error, want rejection", path)
			}
			var wantName InvalidEntryNameError
			if !errors.As(firstErr, &wantName) {
				t.Fatalf("first error = %v (%T), want an InvalidEntryNameError", firstErr, firstErr)
			}

			// A consumer that classifies the above as a package problem and
			// carries on with the same instance.
			legit := &Package{Name: "legit", Version: "1.0"}
			_, err := a.installAPKFiles(t.Context(), tarWith(t,
				tar.Header{Name: "usr", Typeflag: tar.TypeDir, Mode: 0o755},
				tar.Header{Name: "usr/share", Typeflag: tar.TypeDir, Mode: 0o755},
				tar.Header{Name: shared, Typeflag: tar.TypeReg, Mode: 0o644},
			), legit)
			if err == nil {
				t.Fatal("second install succeeded after a failed one; the instance's view of " +
					"which package owns which file is no longer trustworthy, so continuing " +
					"can silently drop a present file from the installed database")
			}
			if !errors.Is(err, ErrInstallAborted) {
				t.Errorf("second error = %v, want it to match ErrInstallAborted so a caller can "+
					"tell 'this instance is done' from 'this package is bad'", err)
			}
			// The original cause must survive, or the operator cannot tell why.
			if !errors.As(err, &wantName) {
				t.Errorf("second error = %v, want it to still carry the original "+
					"InvalidEntryNameError", err)
			}

			// AddInstalledPackage is the record writer and must refuse too:
			// writing a record from a stale ownership view is the corruption.
			if _, err := a.AddInstalledPackage(legit, nil); !errors.Is(err, ErrInstallAborted) {
				t.Errorf("AddInstalledPackage after a failed install = %v, want ErrInstallAborted", err)
			}
		})
	}
}

// The refusal must not fire on a healthy instance: two ordinary packages in
// sequence keep working, or the guard has simply broken installation.
func TestSuccessfulInstallsDoNotPoisonTheInstance(t *testing.T) {
	a := newTestAPKInDir(t)

	for _, name := range []string{"first", "second"} {
		pkg := &Package{Name: name, Version: "1.0", Origin: name}
		_, err := a.installAPKFiles(t.Context(), tarWith(t,
			tar.Header{Name: "usr", Typeflag: tar.TypeDir, Mode: 0o755},
			tar.Header{Name: "usr/" + name + ".txt", Typeflag: tar.TypeReg, Mode: 0o644},
		), pkg)
		if err != nil {
			t.Fatalf("installAPKFiles(%s) = %v, want success", name, err)
		}
	}
}
