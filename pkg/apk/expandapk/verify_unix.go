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

// unlinkedTempFile creates a named temporary file, unlinks it, and returns the
// descriptor only if no other name for the inode survived. It is the weaker half
// of anonymousFile: the fallback for platforms and filesystems with no
// windowless primitive, and the only path on unix outside Linux.
//
// The window between creating the name and unlinking it is exploitable rather
// than theoretical, and two distinct attacks live in it which are not equally
// defensible:
//
//   - Hardlink the name, keeping a second reference to the inode after the
//     unlink. Detectable: the link count is non-zero afterwards, so this
//     function checks it and refuses.
//   - Simply open the name for writing. The unlink then removes the only link,
//     the link count reads zero, the check passes, and the attacker still writes
//     through their descriptor into what this one serves. There is no portable
//     way to count the openers of an inode, so this cannot be detected at all.
//
// What saves the realistic case is ownership rather than either check.
// os.CreateTemp creates at mode 0600 owned by us, so a cache writer running as a
// *different* uid -- the shared-CI case this threat model is about -- cannot open
// it, and where /proc/sys/fs/protected_hardlinks is enabled they cannot hardlink
// a file they neither own nor can read either. That sysctl is not a kernel
// default: the kernel ships it off and distribution sysctl defaults turn it on,
// so a minimal container may not have it at all, leaving the link check above as
// the only thing standing between a different-uid attacker and a second
// reference. Note also that hardlinking needs write access to the containing
// directory rather than read access to the file, so 0600 alone does not prevent
// it. Against a *same-uid*
// attacker none of that holds: they can open it, and if it were created mode
// 0000 instead they own it and can chmod it back. No DAC arrangement helps,
// because they already have every privilege this process has -- they can ptrace
// it too, so the private copy was never the binding constraint for them.
//
// So: integrity holds here against a different-uid cache writer, and does not
// hold against a same-uid one. Closing that properly means verifying at
// consumption rather than ahead of it -- hashing the tar as it is read for
// install and abandoning the layer on mismatch -- which is a larger change than
// this.
func unlinkedTempFile(dir string) (*os.File, error) {
	f, err := os.CreateTemp(dir, ".apko-data-*")
	if err != nil {
		return nil, err
	}
	if err := os.Remove(f.Name()); err != nil && !os.IsNotExist(err) {
		f.Close()
		return nil, fmt.Errorf("unlinking %q: %w", f.Name(), err)
	}

	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		f.Close()
		return nil, fmt.Errorf("stat of %q: %w", f.Name(), err)
	}
	if st.Nlink != 0 {
		f.Close()
		return nil, fmt.Errorf("%q still has %d link(s) after being unlinked, so another process holds a reference to it",
			f.Name(), st.Nlink)
	}
	return f, nil
}
