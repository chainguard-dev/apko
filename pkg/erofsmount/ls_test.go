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

package erofsmount

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	erofs "github.com/erofs/go-erofs"
)

// lsFixture writes a small EROFS image exercising every column of the listing
// — non-root ownership, the special mode bits, a devnode, a symlink — and
// returns it opened for reading. Built with the go-erofs writer directly so
// the expected uid/gid/rdev values are pinned by the test, not derived from
// whatever the host filesystem happens to hold.
func lsFixture(t *testing.T) fs.FS {
	t.Helper()

	path := filepath.Join(t.TempDir(), "image.erofs")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := erofs.Create(f)

	mkdir := func(name string, perm fs.FileMode) {
		t.Helper()
		if err := w.Mkdir(name, perm); err != nil {
			t.Fatalf("Mkdir(%s): %v", name, err)
		}
		chmodChown(t, w, name, perm, 0, 0)
	}
	write := func(name, data string, mode fs.FileMode, uid, gid int) {
		t.Helper()
		fh, err := w.Create(name)
		if err != nil {
			t.Fatalf("Create(%s): %v", name, err)
		}
		if _, err := fh.Write([]byte(data)); err != nil {
			t.Fatalf("Write(%s): %v", name, err)
		}
		if err := fh.Close(); err != nil {
			t.Fatalf("Close(%s): %v", name, err)
		}
		chmodChown(t, w, name, mode, uid, gid)
	}

	mkdir("/usr", 0o755)
	mkdir("/usr/bin", 0o755)
	// A setuid binary owned by a non-root uid/gid: the two things the listing
	// used to lose.
	write("/usr/bin/sudo", "suid", fs.ModeSetuid|0o755, 13, 15)
	write("/usr/bin/plain", "hello", 0o644, 0, 0)
	mkdir("/tmp", fs.ModeSticky|0o777)
	mkdir("/dev", 0o755)
	// rdev per Linux's new_encode_dev(): major 1, minor 3 => 1<<8 | 3.
	if err := w.Mknod("/dev/null", 0o020666, 1<<8|3); err != nil {
		t.Fatalf("Mknod: %v", err)
	}
	chmodChown(t, w, "/dev/null", 0o666, 0, 0)
	if err := w.Symlink("sudo", "/usr/bin/sudo-link"); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("finalize image: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	r, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	img, err := erofs.Open(r)
	if err != nil {
		t.Fatalf("open image: %v", err)
	}
	return img
}

func chmodChown(t *testing.T, w *erofs.Writer, name string, mode fs.FileMode, uid, gid int) {
	t.Helper()
	if err := w.Chmod(name, mode); err != nil {
		t.Fatalf("Chmod(%s): %v", name, err)
	}
	if err := w.Chown(name, uid, gid); err != nil {
		t.Fatalf("Chown(%s): %v", name, err)
	}
	// A fixed mtime keeps the expected listing stable.
	if err := w.Chtimes(name, time.Time{}, time.Unix(1700000000, 0)); err != nil {
		t.Fatalf("Chtimes(%s): %v", name, err)
	}
}

// lsLines runs the listing over fsys and returns it keyed by path, with each
// line split into its whitespace-separated columns (tabwriter pads with
// spaces, so the raw text is not stable enough to compare).
func lsLines(t *testing.T, fsys fs.FS) map[string][]string {
	t.Helper()
	var buf bytes.Buffer
	if err := walkAndPrint(context.Background(), fsys, &buf); err != nil {
		t.Fatalf("walkAndPrint: %v", err)
	}
	out := map[string][]string{}
	for line := range strings.SplitSeq(strings.TrimRight(buf.String(), "\n"), "\n") {
		cols := strings.Fields(line)
		if len(cols) < 6 {
			t.Fatalf("unexpected listing line %q", line)
		}
		// cols: mode uid/gid size date time path [-> target]
		out[cols[5]] = cols
	}
	return out
}

func TestLs_ColumnsFromErofsStat(t *testing.T) {
	got := lsLines(t, NewStack(lsFixture(t)))

	for _, tc := range []struct {
		path             string
		mode, owner, siz string
	}{
		// uid/gid used to always print 0/0: the accessor interfaces it looked
		// for on Sys() do not exist on *erofs.Stat, only fields do.
		{path: "usr/bin/sudo", mode: "-rwsr-xr-x", owner: "13/15", siz: "4"},
		{path: "usr/bin/plain", mode: "-rw-r--r--", owner: "0/0", siz: "5"},
		// siz empty: a directory's size is its dirent block, left as-is.
		{path: "tmp", mode: "drwxrwxrwt", owner: "0/0"},
		// Devices reported their (meaningless) inode size where `tar tv`
		// prints major,minor.
		{path: "dev/null", mode: "crw-rw-rw-", owner: "0/0", siz: "1,3"},
	} {
		cols, ok := got[tc.path]
		if !ok {
			t.Errorf("%s missing from listing", tc.path)
			continue
		}
		if cols[0] != tc.mode {
			t.Errorf("%s mode: got %s, want %s", tc.path, cols[0], tc.mode)
		}
		if cols[1] != tc.owner {
			t.Errorf("%s uid/gid: got %s, want %s", tc.path, cols[1], tc.owner)
		}
		if tc.siz != "" && cols[2] != tc.siz {
			t.Errorf("%s size column: got %s, want %s", tc.path, cols[2], tc.siz)
		}
	}

	// Symlinks keep their target suffix and are not followed for the mode.
	link := got["usr/bin/sudo-link"]
	if link == nil {
		t.Fatal("usr/bin/sudo-link missing from listing")
	}
	if link[0] != "lrwxrwxrwx" {
		t.Errorf("symlink mode: got %s, want lrwxrwxrwx", link[0])
	}
	if want := []string{"->", "sudo"}; len(link) < 8 || link[6] != want[0] || link[7] != want[1] {
		t.Errorf("symlink target: got %v, want ... -> sudo", link)
	}

	// mtime column, fixed by the fixture.
	if cols := got["usr/bin/plain"]; cols[3] != "2023-11-14" {
		t.Errorf("date column: got %s, want 2023-11-14", cols[3])
	}
}

// TestLs_SynthesizedDirsHaveNoStat covers the fallback path: Stack invents
// fs.FileInfo values for parent directories that no layer contains, and those
// carry a nil Sys(), so formatEntry must not depend on *erofs.Stat.
func TestLs_SynthesizedDirsHaveNoStat(t *testing.T) {
	info := &synthInfo{name: "etc", mode: fs.ModeDir | 0o755}
	line := formatEntry(NewStack(), info, "etc")
	cols := strings.Fields(line)
	if cols[0] != "drwxr-xr-x" {
		t.Errorf("mode: got %s, want drwxr-xr-x", cols[0])
	}
	if cols[1] != "0/0" {
		t.Errorf("uid/gid: got %s, want 0/0", cols[1])
	}
}

func TestFormatMode(t *testing.T) {
	for _, tc := range []struct {
		mode fs.FileMode
		want string
	}{
		{0o644, "-rw-r--r--"},
		{fs.ModeDir | 0o755, "drwxr-xr-x"},
		{fs.ModeSymlink | 0o777, "lrwxrwxrwx"},
		{fs.ModeDevice | fs.ModeCharDevice | 0o666, "crw-rw-rw-"},
		{fs.ModeDevice | 0o660, "brw-rw----"},
		{fs.ModeNamedPipe | 0o644, "prw-r--r--"},
		{fs.ModeSocket | 0o755, "srwxr-xr-x"},
		{fs.ModeSetuid | 0o4755, "-rwsr-xr-x"},
		{fs.ModeSetgid | 0o2755, "-rwxr-sr-x"},
		{fs.ModeDir | fs.ModeSticky | 0o1777, "drwxrwxrwt"},
		// Special bit set without the matching execute bit: upper-case.
		{fs.ModeSetuid | 0o4644, "-rwSr--r--"},
		{fs.ModeSetgid | 0o2644, "-rw-r-Sr--"},
		{fs.ModeDir | fs.ModeSticky | 0o1776, "drwxrwxrwT"},
		{fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky | 0o7777, "-rwsrwsrwt"},
	} {
		if got := formatMode(tc.mode); got != tc.want {
			t.Errorf("formatMode(%v): got %s, want %s", tc.mode, got, tc.want)
		}
	}
}

func TestDecodeRdev(t *testing.T) {
	for _, tc := range []struct {
		rdev                uint32
		wantMaj, wantMinPar uint32
	}{
		{1<<8 | 3, 1, 3}, // /dev/null
		{5<<8 | 1, 5, 1}, // /dev/console
		{0, 0, 0},        // unset
		{0xfff00 | 0xff, 0xfff, 0xff},
		// Minor above 8 bits spills into bits 20+ per new_encode_dev.
		{8<<8 | (0x100 << 12), 8, 0x100},
	} {
		maj, min := decodeRdev(tc.rdev)
		if maj != tc.wantMaj || min != tc.wantMinPar {
			t.Errorf("decodeRdev(%#x): got %d,%d want %d,%d", tc.rdev, maj, min, tc.wantMaj, tc.wantMinPar)
		}
	}
}
