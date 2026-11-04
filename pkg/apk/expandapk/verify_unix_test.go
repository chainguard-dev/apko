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

//go:build unix

package expandapk

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func mkfifo(path string) error {
	return syscall.Mkfifo(path, 0o644)
}

// nlinkOf returns the link count of the inode behind f.
//
// The conversion is load-bearing for portability: st_nlink is uint64 on Linux
// but uint16 on darwin, so returning the field directly compiles on only one of
// the platforms apko releases for.
func nlinkOf(t *testing.T, f *os.File) uint64 {
	t.Helper()

	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		t.Fatalf("fstat: %v", err)
	}
	// nolint:unconvert // Redundant on Linux, where st_nlink is already uint64,
	// but required on darwin, where it is uint16. The linter only ever sees the
	// Linux definition.
	return uint64(st.Nlink)
}

// TestPrivateFile covers the unlinked-copy primitive directly.
func TestPrivateFile(t *testing.T) {
	t.Run("has no links at all", func(t *testing.T) {
		// The property the whole design rests on. A single remaining link is a
		// name somebody else can open and write through, which would put the
		// served bytes back under their control.
		dir := t.TempDir()
		f, err := privateFile(dir)
		if err != nil {
			t.Fatalf("privateFile: %v", err)
		}
		defer f.Close()

		if n := nlinkOf(t, f); n != 0 {
			t.Errorf("private copy has %d link(s); it must have none", n)
		}
	})

	t.Run("is unlinked but writable", func(t *testing.T) {
		dir := t.TempDir()
		f, err := privateFile(dir)
		if err != nil {
			t.Fatalf("privateFile: %v", err)
		}
		defer f.Close()

		if _, err := os.Lstat(f.Name()); !os.IsNotExist(err) {
			t.Errorf("%q is still reachable by name (stat err = %v)", f.Name(), err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Errorf("privateFile left %d entries behind in %s", len(entries), dir)
		}

		if _, err := f.Write([]byte("payload")); err != nil {
			t.Fatalf("writing to the private file: %v", err)
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		if got := readAllFrom(t, f); string(got) != "payload" {
			t.Errorf("private file round-trip: got %q", got)
		}
	})

	// The windowless O_TMPFILE path is asserted in verify_linux_test.go, since
	// it is a guarantee only that platform makes.

	t.Run("the named fallback never returns a descriptor that still has a link", func(t *testing.T) {
		// unlinkedTempFile has to publish a name, and anyone with write access to
		// the directory can hardlink it before the unlink lands. They then hold a
		// second reference and can write through it, changing what the verified
		// descriptor serves. protected_hardlinks does not prevent that when the
		// attacker shares our uid, which is the co-tenant case in this threat
		// model, so the link count has to be checked.
		//
		// Driven against unlinkedTempFile directly, because on Linux the
		// O_TMPFILE path would pre-empt the fallback and never exercise it.
		//
		// The race is probabilistic but the assertion is not: whether or not the
		// linker wins any given round, no descriptor handed back may have a
		// surviving link.
		dir := t.TempDir()

		stop := make(chan struct{})
		var linker sync.WaitGroup
		linker.Go(func() {
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				// The file lives in a private 0700 directory, which a different-uid
				// attacker cannot search. This test runs as the same uid, so it can,
				// and the link check is what has to catch it.
				names, _ := filepath.Glob(filepath.Join(dir, ".apko-private-*", ".apko-data-*"))
				for _, name := range names {
					_ = os.Link(name, filepath.Join(dir, fmt.Sprintf("stolen-%d", i)))
				}
			}
		})

		var served, refused int
		for range 2000 {
			f, err := unlinkedTempFile(dir)
			if err != nil {
				refused++
				continue
			}
			served++
			if n := nlinkOf(t, f); n != 0 {
				f.Close()
				close(stop)
				linker.Wait()
				t.Fatalf("unlinkedTempFile returned a descriptor with %d surviving link(s); "+
					"another process can write through that name and change what is served", n)
			}
			f.Close()
		}
		close(stop)
		linker.Wait()

		t.Logf("served=%d refused=%d", served, refused)
		if served == 0 {
			t.Error("every attempt was refused, so this asserted nothing about the served path")
		}
	})

	t.Run("falls back when the preferred directory is not writable", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("running as root; directory modes do not restrict us")
		}
		// A read-only cache directory is a legitimate deployment, and a build over
		// one has to keep working.
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

		f, err := privateFile(dir)
		if err != nil {
			t.Fatalf("privateFile must fall back to the system temp dir, got: %v", err)
		}
		defer f.Close()
		if _, err := os.Lstat(f.Name()); !os.IsNotExist(err) {
			t.Errorf("fallback file %q is still reachable by name", f.Name())
		}
	})
}

// fakeFstat replaces fstatIdentity for the duration of the test. hook is
// called with the file and the number of times it has been statted before, and
// returns the identity to report.
func fakeFstat(t *testing.T, hook func(t *testing.T, f *os.File, call int, real fileIdentity) fileIdentity) {
	t.Helper()
	orig := fstatIdentity
	t.Cleanup(func() { fstatIdentity = orig })

	calls := map[string]int{}
	fstatIdentity = func(f *os.File) (fileIdentity, error) {
		real, err := orig(f)
		if err != nil {
			return real, err
		}
		n := calls[f.Name()]
		calls[f.Name()]++
		return hook(t, f, n, real), nil
	}
}

// gvisorNlink reports what gVisor does for an open file that has been unlinked:
// a link count of 1 instead of 0.
func gvisorNlink(id fileIdentity) fileIdentity {
	if id.nlink == 0 {
		id.nlink = 1
	}
	return id
}

func isData(f *os.File) bool {
	return strings.HasPrefix(filepath.Base(f.Name()), ".apko-data-")
}

// TestUnlinkedTempFileLinkCounts covers how unlinkedTempFile reads link counts
// on filesystems that do not report them the way a native kernel does.
func TestUnlinkedTempFileLinkCounts(t *testing.T) {
	t.Run("an unlinked file still reporting one link is served under gVisor", func(t *testing.T) {
		// gVisor (runsc, GKE Sandbox) reports st_nlink == 1 for every unlinked
		// open file. Refusing on that made every package expansion fail there.
		fakeFstat(t, func(_ *testing.T, _ *os.File, _ int, real fileIdentity) fileIdentity {
			return gvisorNlink(real)
		})

		dir := t.TempDir()
		f, err := unlinkedTempFile(dir)
		if err != nil {
			t.Fatalf("unlinkedTempFile: %v", err)
		}
		defer f.Close()

		if _, err := os.Lstat(f.Name()); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%q is still reachable by name (stat err = %v)", f.Name(), err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Errorf("unlinkedTempFile left %d entries behind in %s: %v", len(entries), dir, entries)
		}
		if _, err := f.Write([]byte("payload")); err != nil {
			t.Fatalf("writing to the private file: %v", err)
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		if got := readAllFrom(t, f); string(got) != "payload" {
			t.Errorf("private file round-trip: got %q", got)
		}
	})

	t.Run("a real second link is refused under gVisor", func(t *testing.T) {
		// Tolerating gVisor's count must not tolerate an actual second name.
		dir := t.TempDir()
		stolen := filepath.Join(dir, "stolen")
		fakeFstat(t, func(t *testing.T, f *os.File, call int, real fileIdentity) fileIdentity {
			if isData(f) && call == 0 {
				if err := os.Link(f.Name(), stolen); err != nil {
					t.Fatalf("linking: %v", err)
				}
				real.nlink++
			}
			return gvisorNlink(real)
		})

		f, err := unlinkedTempFile(dir)
		if err == nil {
			f.Close()
			t.Fatal("unlinkedTempFile served a file with a second name")
		}
		if !strings.Contains(err.Error(), "links before being unlinked") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("a link made after the first stat is refused where counts are honest", func(t *testing.T) {
		// The race the link check exists for: the second name appears after the
		// count was first read but before the unlink, so only the count after
		// the unlink shows it. On a native kernel the probe reads 0, so the 1 on
		// our file cannot be blamed on the filesystem.
		dir := t.TempDir()
		stolen := filepath.Join(dir, "stolen")
		fakeFstat(t, func(t *testing.T, f *os.File, call int, real fileIdentity) fileIdentity {
			if isData(f) && call == 0 {
				if err := os.Link(f.Name(), stolen); err != nil {
					t.Fatalf("linking: %v", err)
				}
			}
			return real
		})

		f, err := unlinkedTempFile(dir)
		if err == nil {
			f.Close()
			t.Fatal("unlinkedTempFile served a file with a second name")
		}
		if !strings.Contains(err.Error(), "still has 1 link(s) after being unlinked") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("a descriptor whose identity changes across the unlink is refused", func(t *testing.T) {
		fakeFstat(t, func(_ *testing.T, f *os.File, call int, real fileIdentity) fileIdentity {
			if isData(f) && call == 1 {
				real.ino++
			}
			return gvisorNlink(real)
		})

		f, err := unlinkedTempFile(t.TempDir())
		if err == nil {
			f.Close()
			t.Fatal("unlinkedTempFile served a descriptor that changed identity")
		}
		if !strings.Contains(err.Error(), "changed identity") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("anything left in the private directory is refused", func(t *testing.T) {
		// rmdir of the private directory is what proves nothing else was created
		// in it during the window.
		fakeFstat(t, func(t *testing.T, f *os.File, call int, real fileIdentity) fileIdentity {
			if isData(f) && call == 0 {
				if err := os.WriteFile(filepath.Join(filepath.Dir(f.Name()), "planted"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			return real
		})

		f, err := unlinkedTempFile(t.TempDir())
		if err == nil {
			f.Close()
			t.Fatal("unlinkedTempFile served a file whose private directory was not empty")
		}
		if !strings.Contains(err.Error(), "removing private directory") {
			t.Errorf("unexpected error: %v", err)
		}
	})
}
