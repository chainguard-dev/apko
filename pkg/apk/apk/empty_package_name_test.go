package apk

import (
	"archive/tar"
	"errors"
	"strings"
	"testing"
)

// A package whose name is empty renders a "P:" line with no value.
// ParseInstalled gates on pkg.Name != "" and so drops the entire record at the
// blank line, which means the package's files are present in the image while
// belonging to no package, and absent from anything derived from the database.
// Writing a record that cannot be read back is never useful.
func TestAddInstalledPackageRejectsEmptyPackageName(t *testing.T) {
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
		{Name: "usr/bin", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: "usr/bin/thing", Typeflag: tar.TypeReg, Size: 5, Mode: 0o755},
	}

	_, err = a.AddInstalledPackage(&Package{Name: "", Version: "1.0", Arch: "x86_64"}, files)
	if err == nil {
		t.Fatal("AddInstalledPackage accepted a package with an empty name, want rejection")
	}
	// The reason must be recoverable without parsing the message. MalformedPackageError's
	// doc offers ErrEmptyName as one of its two reasons and "name" as a Field value;
	// this is the only site that produces them, so without this assertion that
	// contract is prose a caller cannot rely on.
	var mpe MalformedPackageError
	if !errors.As(err, &mpe) {
		t.Fatalf("error = %v (%T), want a MalformedPackageError", err, err)
	}
	if !errors.Is(err, ErrEmptyName) {
		t.Errorf("errors.Is(err, ErrEmptyName) = false, want true; err = %v", err)
	}
	if mpe.Field != "name" {
		t.Errorf("Field = %q, want %q; err = %v", mpe.Field, "name", err)
	}

	after, err := a.GetInstalled()
	if err != nil {
		t.Fatalf("GetInstalled after rejection: %v", err)
	}
	if len(after) != len(before) {
		t.Errorf("installed package count went %d -> %d after a rejected write", len(before), len(after))
	}
}

// The rejection must not cost a legitimate package: a name is the only thing
// required here, and everything else may be empty.
func TestAddInstalledPackageAcceptsMinimalPackage(t *testing.T) {
	a, _, err := testGetTestAPK()
	if err != nil {
		t.Fatalf("testGetTestAPK: %v", err)
	}
	before, err := a.GetInstalled()
	if err != nil {
		t.Fatalf("GetInstalled: %v", err)
	}

	if _, err := a.AddInstalledPackage(&Package{Name: "minimal"}, nil); err != nil {
		t.Fatalf("AddInstalledPackage(minimal) = %v, want success", err)
	}

	after, err := a.GetInstalled()
	if err != nil {
		t.Fatalf("GetInstalled after add: %v", err)
	}
	if len(after) != len(before)+1 {
		t.Fatalf("installed count = %d, want %d", len(after), len(before)+1)
	}
	if got := after[len(after)-1].Name; got != "minimal" {
		t.Errorf("added package name = %q, want %q", got, "minimal")
	}
}

// The read side range-checks the owner on an "M:"/"a:" line, and that error
// aborts the read of the whole database rather than just the bad record. So the
// write side has to refuse the same values, for the same reason the empty name
// and the top-level-directory cases above are refused: a record we cannot read
// back takes everything else down with it.
func TestAddInstalledPackageRejectsOutOfRangeOwner(t *testing.T) {
	cases := []struct {
		name     string
		uid, gid int64
		errMatch string
	}{
		{"uid 2^32", 1 << 32, 0, "invalid uid 4294967296"},
		{"negative uid", -1, 0, "invalid uid -1"},
		{"gid 2^32", 0, 1 << 32, "invalid gid 4294967296"},
		{"negative gid", 0, -1, "invalid gid -1"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			// Skip the test when the ids don't fit an int. On a 32-bit platform
			// archive/tar rejects it before this code sees it.
			uid, gid := idsAsIntOrSkip(t, tt.uid, tt.gid)

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
				{Name: "usr/bin", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "usr/bin/backdoor", Typeflag: tar.TypeReg, Mode: 0o4755, Uid: uid, Gid: gid, Size: 5},
			}

			_, err = a.AddInstalledPackage(&Package{Name: "backdoor", Version: "1.0", Arch: "x86_64"}, files)
			if err == nil {
				t.Fatal("AddInstalledPackage accepted an out-of-range owner, want rejection")
			}
			if !strings.Contains(err.Error(), tt.errMatch) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tt.errMatch)
			}

			// The database must still be readable, which is the whole point.
			after, err := a.GetInstalled()
			if err != nil {
				t.Fatalf("GetInstalled after rejection: %v", err)
			}
			if len(after) != len(before) {
				t.Errorf("installed package count went %d -> %d after a rejected write", len(before), len(after))
			}
		})
	}
}
