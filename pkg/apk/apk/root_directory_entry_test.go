package apk

import (
	"archive/tar"
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
)

// The installed database spells the top-level directory as a bare "F:" with no
// value, and ParseInstalled rejects an "M:" line following it -- an error that
// aborts the entire read, so one such record makes the whole database
// unreadable rather than merely being wrong itself.
//
// A root entry with default ownership and mode emits no M: line and is
// perfectly representable, so only the non-default case is refused. Before the
// parent-walk fix these inputs could not be reached at all: "//" hung inside
// removeOrphanedEntries, so the reject rows below are also the regression test
// for that, and they run under a watchdog because a revert would otherwise
// wedge the test binary instead of failing it.
func TestAddInstalledPackageRejectsUnrepresentableRootPermissions(t *testing.T) {
	cases := []struct {
		name string
		file tar.Header
	}{
		{"root dir, non-default mode", tar.Header{Name: "/", Typeflag: tar.TypeDir, Mode: 0o700}},
		{"root dir, non-root owner", tar.Header{Name: "/", Typeflag: tar.TypeDir, Mode: 0o755, Uid: 1000}},
		{"root dir, non-root group", tar.Header{Name: "/", Typeflag: tar.TypeDir, Mode: 0o755, Gid: 1000}},
		{"double slash, non-default mode", tar.Header{Name: "//", Typeflag: tar.TypeDir, Mode: 0o700}},
		{"empty name, non-default mode", tar.Header{Name: "", Typeflag: tar.TypeDir, Mode: 0o700}},
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

			var addErr error
			mustNotHang(t, "AddInstalledPackage("+tc.file.Name+")", func() {
				_, addErr = a.AddInstalledPackage(&Package{Name: "pkg", Version: "1.0"},
					[]tar.Header{tc.file})
			})
			if addErr == nil {
				t.Fatalf("AddInstalledPackage(%q, mode %04o) = nil error, want rejection",
					tc.file.Name, tc.file.Mode)
			}
			if !strings.Contains(addErr.Error(), "top-level directory") {
				t.Errorf("error = %q, want it to name the top-level directory", addErr.Error())
			}

			// The rejection must leave the database readable and unchanged.
			after, err := a.GetInstalled()
			if err != nil {
				t.Fatalf("GetInstalled after rejection: %v; the database was left unparseable", err)
			}
			if len(after) != len(before) {
				t.Errorf("installed count went %d -> %d after a rejected write", len(before), len(after))
			}
		})
	}
}

// A root entry with default ownership and mode is representable and was
// recorded correctly before this change, so it must keep working: rejecting it
// would be a regression, not a fix. Every spelling of the root normalises to
// the same bare "F:" marker rather than emitting "F:/" for some of them.
func TestAddInstalledPackageAcceptsRepresentableRootEntry(t *testing.T) {
	cases := []struct {
		name string
		file tar.Header
	}{
		{"root dir, default mode", tar.Header{Name: "/", Typeflag: tar.TypeDir, Mode: 0o755}},
		{"double slash, default mode", tar.Header{Name: "//", Typeflag: tar.TypeDir, Mode: 0o755}},
		{"empty name, default mode", tar.Header{Name: "", Typeflag: tar.TypeDir, Mode: 0o755}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, _, err := testGetTestAPK()
			if err != nil {
				t.Fatalf("testGetTestAPK: %v", err)
			}

			var got []byte
			var addErr error
			mustNotHang(t, "AddInstalledPackage("+tc.file.Name+")", func() {
				got, addErr = a.AddInstalledPackage(&Package{Name: "rooted", Version: "1.0"},
					[]tar.Header{tc.file})
			})
			if addErr != nil {
				t.Fatalf("AddInstalledPackage(%q, mode %04o) = %v, want success",
					tc.file.Name, tc.file.Mode, addErr)
			}

			// Every root spelling must produce the bare marker, never "F:/".
			if !strings.Contains(string(got), "\nF:\n") {
				t.Errorf("record does not contain the bare top-level marker:\n%s", got)
			}
			if strings.Contains(string(got), "F:/") {
				t.Errorf("record spells the root as a named directory:\n%s", got)
			}

			// And it must still be readable, which "F:" followed by "M:" is not.
			pkgs, err := a.GetInstalled()
			if err != nil {
				t.Fatalf("GetInstalled after add: %v; the record is unreadable", err)
			}
			if pkgs[len(pkgs)-1].Name != "rooted" {
				t.Errorf("added package = %q, want %q", pkgs[len(pkgs)-1].Name, "rooted")
			}
		})
	}
}

// Ordinary directory entries must be unaffected: the guard applies only to
// names that denote the root itself.
func TestAddInstalledPackageAcceptsOrdinaryDirectoryEntries(t *testing.T) {
	a, _, err := testGetTestAPK()
	if err != nil {
		t.Fatalf("testGetTestAPK: %v", err)
	}
	before, err := a.GetInstalled()
	if err != nil {
		t.Fatalf("GetInstalled: %v", err)
	}

	files := []tar.Header{
		// "." and "./" denote the package root, not the filesystem root, and
		// are ordinary entries that must keep working -- a guard widened to
		// catch them would be over-eager.
		{Name: "./", Typeflag: tar.TypeDir, Mode: 0o711},
		{Name: "usr", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: "usr/bin", Typeflag: tar.TypeDir, Mode: 0o700},
		{Name: "usr/bin/thing", Typeflag: tar.TypeReg, Size: 1, Mode: 0o755},
	}
	got, err := a.AddInstalledPackage(&Package{Name: "ordinary", Version: "1.0"}, files)
	if err != nil {
		t.Fatalf("AddInstalledPackage with ordinary directories = %v, want success", err)
	}
	// A non-default mode on a NAMED directory still records its M: line; only
	// the top-level directory cannot carry one.
	if !strings.Contains(string(got), "M:0:0:0700") {
		t.Errorf("record lost the M: line for usr/bin:\n%s", got)
	}
	// "." is a named directory, not the root, so it must render as such. The
	// root normalisation must not swallow it into the bare marker.
	// "." is a named directory, not the root, so it must render as such AND be
	// able to carry its own M: line. Only the bare top-level marker cannot.
	if !strings.Contains(string(got), "\nF:.\nM:0:0:0711\n") {
		t.Errorf("the \"./\" entry did not render as F:. with its own M: line -- the root "+
			"normalisation or the guard is too broad and caught a named directory:\n%s", got)
	}

	after, err := a.GetInstalled()
	if err != nil {
		t.Fatalf("GetInstalled after add: %v", err)
	}
	if len(after) != len(before)+1 {
		t.Fatalf("installed count = %d, want %d", len(after), len(before)+1)
	}
	if got := after[len(after)-1].Name; got != "ordinary" {
		t.Errorf("added package = %q, want %q", got, "ordinary")
	}
}

// The guard must also hold when reached the way a real build reaches it:
// installAPKFiles returns the headers that implementation.go hands straight to
// AddInstalledPackage, and it is that composition -- not a synthetic header
// list -- that hung before the parent-walk fix.
func TestInstallPathRejectsUnrepresentableRootPermissions(t *testing.T) {
	ctx := t.Context()
	base := filepath.Join(t.TempDir(), "base")
	fsys := apkfs.DirFS(ctx, base, apkfs.WithCreateDir())
	if fsys == nil {
		t.Fatalf("failed to create dirfs for base %s", base)
	}
	a, err := New(ctx, WithFS(fsys))
	if err != nil {
		t.Fatalf("apk.New: %v", err)
	}

	// AddInstalledPackage opens the database before validating, so without its
	// parent directory the open fails first and the assertion below would be
	// testing the wrong error.
	if err := fsys.MkdirAll(filepath.Dir(installedFilePath), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, h := range []tar.Header{
		{Name: "//", Typeflag: tar.TypeDir, Mode: 0o700},
		{Name: "etc", Typeflag: tar.TypeDir, Mode: 0o755},
	} {
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatalf("WriteHeader(%q): %v", h.Name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}

	files, err := a.installAPKFiles(ctx, bytes.NewReader(buf.Bytes()),
		&Package{Name: "hostile", Version: "1.0"})
	if err != nil {
		t.Fatalf("installAPKFiles: %v", err)
	}

	var addErr error
	mustNotHang(t, "AddInstalledPackage via the install path", func() {
		_, addErr = a.AddInstalledPackage(&Package{Name: "hostile", Version: "1.0"}, files)
	})
	if addErr == nil {
		t.Fatal("a package carrying a root directory entry with non-default mode was accepted")
	}
	if !strings.Contains(addErr.Error(), "top-level directory") {
		t.Errorf("error = %q, want it to name the top-level directory", addErr.Error())
	}
}
