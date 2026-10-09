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
				entries, err := os.ReadDir(dir)
				if err != nil {
					continue
				}
				for _, e := range entries {
					if !strings.HasPrefix(e.Name(), ".apko-data-") {
						continue
					}
					_ = os.Link(filepath.Join(dir, e.Name()),
						filepath.Join(dir, fmt.Sprintf("stolen-%d", i)))
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
