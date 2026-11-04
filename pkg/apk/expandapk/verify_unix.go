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
	"os"

	"golang.org/x/sys/unix"
)

// openNonblocking opens path read-only without blocking, so that a FIFO planted
// where a regular file was expected cannot hang the open. openRegular inspects
// the descriptor before reading from it.
func openNonblocking(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK, 0)
}

func clearNonblock(f *os.File) error {
	return unix.SetNonblock(int(f.Fd()), false)
}

// fileIdentity is the part of fstat(2) that unlinkedTempFile reasons about.
type fileIdentity struct {
	dev, ino, nlink uint64
}

// fstatIdentity is a variable so tests can stand in for filesystems whose link
// counts do not behave like a native kernel's.
var fstatIdentity = func(f *os.File) (fileIdentity, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return fileIdentity{}, err
	}
	// nolint:unconvert // The field widths differ by platform (st_dev is int32
	// and st_nlink uint16 on darwin, st_nlink uint32 on linux/arm64), so these
	// are only redundant on some of the platforms apko builds for.
	return fileIdentity{dev: uint64(st.Dev), ino: uint64(st.Ino), nlink: uint64(st.Nlink)}, nil
}

// unlinkedTempFile creates a named temporary file, unlinks it, and returns the
// descriptor only if no other name for the inode survived. It is the weaker half
// of anonymousFile: the fallback for platforms and filesystems with no
// windowless primitive, and the only path on unix outside Linux.
//
// The window between creating the name and unlinking it is exploitable rather
// than theoretical, and two distinct attacks live in it:
//
//   - Hardlink the name, keeping a second reference to the inode after the
//     unlink.
//   - Simply open the name for writing. The unlink then removes the only link,
//     the link count reads zero, and the attacker still writes through their
//     descriptor into what this one serves. There is no portable way to count
//     the openers of an inode, so this cannot be detected at all.
//
// Both need the attacker to resolve the name, so the file is created inside a
// fresh directory of its own, made by os.MkdirTemp at mode 0700 and owned by us.
// Nobody without our uid (or root) can search it, so nobody else can open or
// hardlink anything in it during the window, whatever the directory around it
// permits and whether or not protected_hardlinks is enabled. Removing that
// directory once the file is unlinked also proves nothing else was created in
// it: rmdir fails on a directory that is not empty.
//
// The link count is still checked, as evidence rather than as the defence, and
// it has to be read carefully because not every filesystem reports it the way a
// native kernel does. Under gVisor (runsc, GKE Sandbox), an open file that has
// been unlinked still reports st_nlink == 1. Refusing on that alone made every
// package expansion fail there. So:
//
//   - Before the unlink the count must be exactly 1, our own name. Anything more
//     is a second name, made before we looked; refused everywhere.
//   - After the unlink the descriptor must still refer to the inode we created
//     (same st_dev and st_ino) and the count must be 0.
//   - A count of 1 after the unlink is accepted only if the filesystem is shown
//     to report that for every unlinked open file: a probe file, created and
//     unlinked the same way in the same parent, must report 1 as well. On a
//     filesystem whose counts are honest the probe reads 0, and a 1 on our file
//     means a real second name, which is refused exactly as before.
//
// What this leaves open is the same as before, and narrower: an attacker with
// our uid can still open the file in the window (undetectable on any
// filesystem), and on a filesystem that misreports counts, one that hardlinks
// between the first fstat and the unlink goes unnoticed. Neither is reachable
// by a different-uid cache writer -- the shared-CI case this threat model is
// about -- because neither can resolve a name inside the 0700 directory. Against
// a same-uid attacker no DAC arrangement helps: they already have every
// privilege this process has and can ptrace it, so the private copy was never
// the binding constraint for them. Closing that properly means verifying at
// consumption rather than ahead of it -- hashing the tar as it is read for
// install and abandoning the layer on mismatch -- which is a larger change than
// this.
func unlinkedTempFile(dir string) (*os.File, error) {
	f, before, after, err := createAndUnlink(dir, ".apko-data-*")
	if err != nil {
		return nil, err
	}

	switch {
	case after.nlink == 0:
		return f, nil
	case after.nlink == 1 && before.nlink == 1:
		lies, err := unlinkedLinkCountMisreported(dir)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("%q still has 1 link after being unlinked, and probing whether the filesystem reports that for every unlinked file failed: %w",
				f.Name(), err)
		}
		if lies {
			return f, nil
		}
	}
	f.Close()
	return nil, fmt.Errorf("%q still has %d link(s) after being unlinked, so another process holds a reference to it",
		f.Name(), after.nlink)
}

// unlinkedLinkCountMisreported reports whether the filesystem holding dir
// reports a link count of 1 for an open file that has been unlinked, as gVisor
// does. It is only consulted after our own file reads 1, so it costs nothing on
// a filesystem that reports counts honestly.
func unlinkedLinkCountMisreported(dir string) (bool, error) {
	probe, _, after, err := createAndUnlink(dir, ".apko-probe-*")
	if err != nil {
		return false, err
	}
	probe.Close()
	return after.nlink == 1, nil
}

// createAndUnlink creates a file matching pattern in a fresh 0700 directory
// under dir, unlinks the file, removes the directory, and returns the open
// descriptor with its identity before and after. It refuses outright when the
// directory could not be removed, when the count before the unlink was not
// exactly 1, or when the descriptor no longer refers to the inode it created.
// The caller judges the count after the unlink.
func createAndUnlink(dir, pattern string) (*os.File, fileIdentity, fileIdentity, error) {
	private, err := os.MkdirTemp(dir, ".apko-private-*")
	if err != nil {
		return nil, fileIdentity{}, fileIdentity{}, err
	}

	f, err := os.CreateTemp(private, pattern)
	if err != nil {
		_ = os.Remove(private)
		return nil, fileIdentity{}, fileIdentity{}, err
	}

	fail := func(err error) (*os.File, fileIdentity, fileIdentity, error) {
		f.Close()
		_ = os.Remove(f.Name())
		_ = os.Remove(private)
		return nil, fileIdentity{}, fileIdentity{}, err
	}

	before, err := fstatIdentity(f)
	if err != nil {
		return fail(fmt.Errorf("stat of %q: %w", f.Name(), err))
	}
	if before.nlink != 1 {
		return fail(fmt.Errorf("%q has %d links before being unlinked, so another process made a second name for it",
			f.Name(), before.nlink))
	}

	if err := os.Remove(f.Name()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fail(fmt.Errorf("unlinking %q: %w", f.Name(), err))
	}
	if err := os.Remove(private); err != nil {
		return fail(fmt.Errorf("removing private directory %q, which should now be empty: %w", private, err))
	}

	after, err := fstatIdentity(f)
	if err != nil {
		return fail(fmt.Errorf("stat of %q: %w", f.Name(), err))
	}
	if after.dev != before.dev || after.ino != before.ino {
		return fail(fmt.Errorf("%q changed identity across its unlink (dev/ino %d/%d -> %d/%d)",
			f.Name(), before.dev, before.ino, after.dev, after.ino))
	}
	return f, before, after, nil
}
