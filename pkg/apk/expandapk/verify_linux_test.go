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

//go:build linux

package expandapk

import (
	"crypto/sha256"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// TestAnonymousFileLeavesNoWindow asserts the property that makes Linux the
// strong path: O_TMPFILE never publishes a name, so unlike the create-then-unlink
// fallback there is no interval in which another process could hardlink or open
// the inode. Verified by watching the directory throughout -- there is never a
// name to steal, so the fallback's link check has nothing to catch.
//
// Linux-only by construction: O_TMPFILE is a Linux extension and is not defined
// on the other platforms apko releases for.
func TestAnonymousFileLeavesNoWindow(t *testing.T) {
	dir := t.TempDir()
	fd, err := unix.Open(dir, unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, 0o600)
	if err != nil {
		t.Skipf("O_TMPFILE unsupported here: %v", err)
	}
	f := os.NewFile(uintptr(fd), "")
	defer f.Close()

	if n := nlinkOf(t, f); n != 0 {
		t.Errorf("O_TMPFILE inode has %d link(s), want 0", n)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("O_TMPFILE created %d directory entries, want none: %v", len(entries), entries)
	}
}

// TestVerifiedPackageDataRejectionLeaksNothing guards a consequence of reading
// the section only once: the private copy has to be created before the digest is
// known, so every rejection path now has a descriptor to dispose of. Leaking it
// would cost an fd and a full uncompressed copy of the data section per rejected
// entry -- and rejections are attacker-triggerable, which turns a leak into a way
// to exhaust the process.
//
// Linux-only because it counts descriptors via /proc/self/fd; the property it
// checks is not platform-specific.
func TestVerifiedPackageDataRejectionLeaksNothing(t *testing.T) {
	dir := t.TempDir()
	a, _, _ := dataSection(t, dir, []byte("this stands in for the package data tar"))

	openFDs := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Skipf("cannot read /proc/self/fd: %v", err)
		}
		return len(entries)
	}

	// Warm up once: the first call can populate pools and lazily open things that
	// are not leaks, which would otherwise read as a constant offset.
	if _, err := a.VerifiedPackageData(make([]byte, sha256.Size)); err == nil {
		t.Fatal("a zero digest should not have verified")
	}

	before := openFDs()
	for range 50 {
		f, err := a.VerifiedPackageData(make([]byte, sha256.Size))
		if err == nil {
			f.Close()
			t.Fatal("a zero digest should not have verified")
		}
	}
	if after := openFDs(); after > before {
		t.Errorf("50 rejected verifications leaked %d descriptor(s) (%d -> %d)", after-before, before, after)
	}
}

// TestAnonymousFilePrefersTmpfile pins that the Linux implementation actually
// takes the O_TMPFILE path rather than silently degrading to the weaker
// fallback. Without this, a regression that broke the O_TMPFILE call would leave
// every test still passing via unlinkedTempFile, and the platform's whole
// advantage would be lost unnoticed.
func TestAnonymousFilePrefersTmpfile(t *testing.T) {
	dir := t.TempDir()

	// unlinkedTempFile is the only other path, and it is distinguishable: it
	// names the file before unlinking it, so its descriptor carries that name.
	// O_TMPFILE's does not.
	f, err := anonymousFile(dir)
	if err != nil {
		t.Fatalf("anonymousFile: %v", err)
	}
	defer f.Close()

	if probe, err := unix.Open(dir, unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, 0o600); err != nil {
		t.Skipf("O_TMPFILE unsupported on this filesystem: %v", err)
	} else {
		_ = unix.Close(probe)
	}

	if got := f.Name(); got != dir+"/(unnamed)" {
		t.Errorf("anonymousFile returned %q, want the O_TMPFILE placeholder %q; "+
			"it fell back to the weaker named path on a filesystem that supports O_TMPFILE",
			got, dir+"/(unnamed)")
	}
}
