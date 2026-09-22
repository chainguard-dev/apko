package apk

import (
	"archive/tar"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Entry names are not the only attacker-influenced data rendered into database
// lines. PackageToInstalled writes package metadata verbatim, and those values
// come from .PKGINFO, which apko parses with go-ini -- a parser that accepts
// multi-line quoted values even though apk-tools does not. ParsePackageInfo now
// rejects such values, but AddInstalledPackage is exported and callers can
// construct a Package directly, so the sink validates the rendered record too.
func TestAddInstalledPackageRejectsNewlinesInMetadata(t *testing.T) {
	const forge = "\n\nP:totally-not-malware\nV:9.9.9\nA:x86_64\nL:MIT"
	cases := []struct {
		name string
		pkg  *Package
	}{
		{"name", &Package{Name: "innocent" + forge, Version: "1.0"}},
		{"version", &Package{Name: "innocent", Version: "1.0" + forge}},
		{"arch", &Package{Name: "innocent", Version: "1.0", Arch: "x86_64" + forge}},
		{"description", &Package{Name: "innocent", Version: "1.0", Description: "harmless" + forge}},
		{"license", &Package{Name: "innocent", Version: "1.0", License: "MIT" + forge}},
		{"origin", &Package{Name: "innocent", Version: "1.0", Origin: "innocent" + forge}},
		{"maintainer", &Package{Name: "innocent", Version: "1.0", Maintainer: "someone" + forge}},
		{"url", &Package{Name: "innocent", Version: "1.0", URL: "http://example.com" + forge}},
		{"repo commit", &Package{Name: "innocent", Version: "1.0", RepoCommit: "abc123" + forge}},
		{"dependencies", &Package{Name: "innocent", Version: "1.0", Dependencies: []string{"libc" + forge}}},
		{"provides", &Package{Name: "innocent", Version: "1.0", Provides: []string{"so:libfoo.so.1" + forge}}},
		{"replaces", &Package{Name: "innocent", Version: "1.0", Replaces: []string{"oldfoo" + forge}}},
		// InstallIf is the one repeated field PackageToInstalled renders with %s
		// over the slice rather than strings.Join, so it emits Go bracket
		// notation ("i:[a b]") and is not covered by any per-field enumeration.
		// These rows therefore exercise the rendered-line backstop itself, which
		// is exactly what it exists for.
		{"install if, first element", &Package{Name: "innocent", Version: "1.0", InstallIf: []string{"cond" + forge}}},
		{"install if, later element", &Package{Name: "innocent", Version: "1.0", InstallIf: []string{"first", "cond" + forge}}},
		{"carriage return only", &Package{Name: "innocent", Version: "1.0", Description: "a\rb"}},
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

			files := []tar.Header{{Name: "usr", Typeflag: tar.TypeDir, Mode: 0o755}}
			if _, err := a.AddInstalledPackage(tc.pkg, files); err == nil {
				t.Fatalf("AddInstalledPackage with a newline in %s = nil error, want rejection", tc.name)
			}

			after, err := a.GetInstalled()
			if err != nil {
				t.Fatalf("GetInstalled after rejection: %v", err)
			}
			if len(after) != len(before) {
				t.Errorf("%s: installed count went %d -> %d after a rejected write", tc.name, len(before), len(after))
			}
			for _, p := range after {
				if p.Name == "totally-not-malware" {
					t.Errorf("%s: forged package present in installed db", tc.name)
				}
			}
		})
	}
}

// A PAX checksum record reaches the Z: line verbatim when it already carries a
// Q1 prefix, and installAPKFiles only recomputes that record for regular files
// -- symlink and hardlink entries pass the attacker's value through untouched.
func TestAddInstalledPackageRejectsNewlineInPaxChecksum(t *testing.T) {
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
		{
			Name: "usr/link", Typeflag: tar.TypeReg, Size: 1, Mode: 0o644,
			PAXRecords: map[string]string{
				paxRecordsChecksumKey: "Q1AAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\nP:forged-via-pax\nV:9.9.9\nA:x86_64",
			},
		},
	}

	if _, err := a.AddInstalledPackage(&Package{Name: "innocent", Version: "1.0"}, files); err == nil {
		t.Fatal("AddInstalledPackage accepted a PAX checksum containing a newline, want rejection")
	}

	after, err := a.GetInstalled()
	if err != nil {
		t.Fatalf("GetInstalled after rejection: %v", err)
	}
	if len(after) != len(before) {
		t.Errorf("installed count went %d -> %d after a rejected write", len(before), len(after))
	}
	for _, p := range after {
		if p.Name == "forged-via-pax" {
			t.Error("forged package injected through the Z: checksum line")
		}
	}
}

// The stated rationale for validating before opening the database file is that
// a rejected package must not leave anything behind. That needs a live oracle:
// newTestAPKInDir builds a DirFS over an empty temp dir where the parent of
// installedFilePath does not exist, so OpenFile(O_CREATE) fails regardless of
// guard placement and the assertion would hold vacuously.
//
// The precondition therefore runs inside EACH subtest's own filesystem. Putting
// it in a sibling subtest is not enough -- deleting this loop's MkdirAll would
// then restore the vacuity and re-hide the mutant this test exists to kill.
func TestAddInstalledPackageDoesNotCreateTheDBWhenRejected(t *testing.T) {
	cases := []struct {
		name  string
		pkg   *Package
		files []tar.Header
	}{
		{
			name:  "control character in an entry name",
			pkg:   &Package{Name: "innocent", Version: "1.0"},
			files: []tar.Header{{Name: "usr/ev\nil.txt", Typeflag: tar.TypeReg, Size: 1, Mode: 0o644}},
		},
		{
			// The earliest of the three guards, so this pins that OpenFile sits
			// below it too. An empty *entry* name is deliberately not here: since
			// #2389 that is the top-level directory and is accepted.
			name:  "empty package name",
			pkg:   &Package{Name: "", Version: "1.0"},
			files: []tar.Header{{Name: "usr/readme.txt", Typeflag: tar.TypeReg, Size: 1, Mode: 0o644}},
		},
		{
			// Rejected by the rendered-line guard rather than the entry-name
			// guard, so this pins that OpenFile sits below *both*.
			name:  "newline in package metadata, entry names clean",
			pkg:   &Package{Name: "innocent", Version: "1.0\n\nP:forged\nV:9.9.9"},
			files: []tar.Header{{Name: "usr/readme.txt", Typeflag: tar.TypeReg, Size: 1, Mode: 0o644}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newTestAPKInDir(t)
			if err := a.fs.MkdirAll(filepath.Dir(installedFilePath), 0o755); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}

			// Precondition, in THIS subtest's filesystem: OpenFile must be able
			// to create the database here, or the assertion below proves nothing.
			f, err := a.fs.OpenFile(installedFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
			if err != nil {
				t.Fatalf("precondition: OpenFile(%q) = %v; the assertion below would hold "+
					"vacuously in this filesystem", installedFilePath, err)
			}
			f.Close()
			if err := a.fs.Remove(installedFilePath); err != nil {
				t.Fatalf("removing the probe file: %v", err)
			}

			if _, err := a.AddInstalledPackage(tc.pkg, tc.files); err == nil {
				t.Fatalf("AddInstalledPackage(%s) = nil error, want rejection", tc.name)
			}
			if _, err := a.fs.Stat(installedFilePath); err == nil {
				t.Errorf("rejected AddInstalledPackage(%s) created %s; every guard must run "+
					"before OpenFile", tc.name, installedFilePath)
			}
		})
	}
}

// The rejection messages quote attacker-controlled data back to the operator, so
// they are themselves a sink: an unescaped newline in a package name or entry
// path would forge log lines from the very input the error exists to report, and
// an unbounded value would turn a hostile megabyte description into a megabyte
// log line.
func TestRejectionErrorsEscapeAttackerControlledData(t *testing.T) {
	const forge = "\n\nP:totally-not-malware\nV:9.9.9"

	t.Run("entry name error escapes the path", func(t *testing.T) {
		err := validateEntryName("innocent", "usr/readme.txt"+forge)
		if err == nil {
			t.Fatal("validateEntryName accepted a forging name, want rejection")
		}
		if strings.ContainsAny(err.Error(), "\n\r") {
			t.Errorf("error contains a raw newline: %s", strconv.Quote(err.Error()))
		}
	})

	t.Run("entry name error escapes the package name", func(t *testing.T) {
		err := validateEntryName("innocent"+forge, "usr/ev\nil")
		if err == nil {
			t.Fatal("validateEntryName accepted a forging name, want rejection")
		}
		if strings.ContainsAny(err.Error(), "\n\r") {
			t.Errorf("error contains a raw newline: %s", strconv.Quote(err.Error()))
		}
	})

	t.Run("rendered line error escapes the line", func(t *testing.T) {
		a, _, aerr := testGetTestAPK()
		if aerr != nil {
			t.Fatalf("testGetTestAPK: %v", aerr)
		}
		files := []tar.Header{{Name: "usr", Typeflag: tar.TypeDir, Mode: 0o755}}
		_, err := a.AddInstalledPackage(&Package{Name: "innocent", Version: "1.0", Description: "x" + forge}, files)
		if err == nil {
			t.Fatal("AddInstalledPackage accepted a forging description, want rejection")
		}
		if strings.ContainsAny(err.Error(), "\n\r") {
			t.Errorf("error contains a raw newline: %s", strconv.Quote(err.Error()))
		}
	})

	t.Run("a hostile oversized value is truncated", func(t *testing.T) {
		err := validateEntryName("innocent", "usr/"+strings.Repeat("A", 10000)+"\n")
		if err == nil {
			t.Fatal("want rejection")
		}
		if len(err.Error()) > 600 {
			t.Errorf("error message is %d bytes; an attacker-sized value must be truncated", len(err.Error()))
		}
	})
}

// Only \n and \r can terminate a record in the apk database, so the wider
// control set applied to entry names must NOT be applied to metadata. Rejecting
// a tab or DEL in a description would be over-rejection that breaks real
// packages; this pins the accept side of that deliberate asymmetry.
func TestAddInstalledPackageAcceptsNonNewlineControlBytesInMetadata(t *testing.T) {
	for _, tc := range []struct{ name, desc string }{
		{"tab", "an ordinary\tdescription"},
		{"vertical tab", "an ordinary\vdescription"},
		{"form feed", "an ordinary\fdescription"},
		{"escape byte", "an ordinary\x1bdescription"},
		{"DEL byte", "an ordinary\x7fdescription"},
		{"U+2028 line separator", "an ordinary\u2028description"},
		{"U+2029 paragraph separator", "an ordinary\u2029description"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _, err := testGetTestAPK()
			if err != nil {
				t.Fatalf("testGetTestAPK: %v", err)
			}
			pkg := &Package{Name: "legit", Version: "1.0", Arch: "x86_64", Description: tc.desc}
			files := []tar.Header{{Name: "usr", Typeflag: tar.TypeDir, Mode: 0o755}}
			if _, err := a.AddInstalledPackage(pkg, files); err != nil {
				t.Fatalf("AddInstalledPackage with %s in the description = %v, want success: "+
					"only \\n and \\r can forge a record, so rejecting %q is over-rejection",
					tc.name, err, tc.desc)
			}
		})
	}
}

// The rendered-line rejection must be matchable as ErrEmbeddedNewline. Without
// this, apk.ErrEmbeddedNewline is asserted by no test in the repository and the
// errors.Is contract MalformedPackageError documents is unenforced.
func TestRenderedLineRejectionMatchesErrEmbeddedNewline(t *testing.T) {
	for _, tc := range []struct {
		name string
		pkg  *Package
	}{
		{"newline in description", &Package{Name: "innocent", Version: "1.0", Description: "x\n\nP:forged"}},
		{"carriage return in version", &Package{Name: "innocent", Version: "1.0\rP:forged"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _, aerr := testGetTestAPK()
			if aerr != nil {
				t.Fatalf("testGetTestAPK: %v", aerr)
			}
			_, err := a.AddInstalledPackage(tc.pkg,
				[]tar.Header{{Name: "usr", Typeflag: tar.TypeDir, Mode: 0o755}})
			if err == nil {
				t.Fatal("want rejection")
			}
			if !errors.Is(err, ErrEmbeddedNewline) {
				t.Errorf("error = %v, want it to match ErrEmbeddedNewline", err)
			}
			if errors.Is(err, ErrEmptyName) {
				t.Errorf("error = %v also matches an unrelated reason", err)
			}
			got, ok := errors.AsType[MalformedPackageError](err)
			if !ok {
				t.Errorf("error = %v (%T), want a MalformedPackageError", err, err)
			} else if got.Package != "innocent" {
				t.Errorf("MalformedPackageError.Package = %q, want %q", got.Package, "innocent")
			}
		})
	}
}

// MalformedPackageError repeats the package name, which is as attacker-
// controlled as the value. The escaping table above covers the package name
// only for InvalidEntryNameError.
func TestMalformedPackageErrorEscapesAttackerControlledData(t *testing.T) {
	const forge = "\n\nP:totally-not-malware\nV:9.9.9"
	for _, tc := range []struct {
		name string
		pkg  *Package
	}{
		{"package name reaches the rejection", &Package{Name: "innocent" + forge, Version: "1.0"}},
		{"offending value reaches the rejection", &Package{Name: "innocent", Version: "1.0", Description: "x" + forge}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _, aerr := testGetTestAPK()
			if aerr != nil {
				t.Fatalf("testGetTestAPK: %v", aerr)
			}
			_, err := a.AddInstalledPackage(tc.pkg,
				[]tar.Header{{Name: "usr", Typeflag: tar.TypeDir, Mode: 0o755}})
			if err == nil {
				t.Fatalf("want rejection")
			}
			if strings.ContainsAny(err.Error(), "\n\r") {
				t.Errorf("rejection carries a raw newline and can forge log lines: %s",
					strconv.Quote(err.Error()))
			}
		})
	}
}

// A rejection must still say what it rejected. Every other assertion here is an
// upper bound, so a truncateForError that returned "" would satisfy them all.
func TestRejectionErrorsStillIdentifyTheOffendingValue(t *testing.T) {
	t.Run("short value is reported in full", func(t *testing.T) {
		err := validateEntryName("mypkg", "usr/ev\nil.txt")
		if !strings.Contains(err.Error(), `usr/ev\nil.txt`) {
			t.Errorf("message does not name the offending path: %s", strconv.Quote(err.Error()))
		}
		if !strings.Contains(err.Error(), "mypkg") {
			t.Errorf("message does not name the package: %s", strconv.Quote(err.Error()))
		}
	})

	t.Run("oversized value keeps a usable prefix and is marked truncated", func(t *testing.T) {
		err := validateEntryName("mypkg", "usr/"+strings.Repeat("A", 10000)+"\n")
		msg := err.Error()
		if !strings.Contains(msg, "usr/"+strings.Repeat("A", 60)) {
			t.Errorf("truncation discarded the usable prefix: %s", strconv.Quote(msg))
		}
		if !strings.Contains(msg, "(truncated)") {
			t.Errorf("truncation is not signalled: %s", strconv.Quote(msg))
		}
	})
}
