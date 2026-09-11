package apk

import (
	"archive/tar"
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
	if !strings.Contains(err.Error(), "empty name") {
		t.Errorf("error = %q, want it to mention the empty name", err.Error())
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
