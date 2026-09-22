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
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// anonymousFile creates a file in dir that has no name.
//
// O_TMPFILE creates the inode without ever linking it into the directory, so
// there is no window in which another process could reach it and nothing for the
// link check in unlinkedTempFile to catch. This is the strong path, and it is
// why Linux gets a separate implementation at all.
//
// Not every Linux filesystem implements O_TMPFILE, so this still falls back.
// That fallback is weaker; see unlinkedTempFile.
func anonymousFile(dir string) (*os.File, error) {
	if fd, err := unix.Open(dir, unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, 0o600); err == nil {
		// The descriptor has no name. Give it a recognisable one for error
		// messages; nothing resolves it, and IsValid skips the name check for a
		// private copy.
		return os.NewFile(uintptr(fd), filepath.Join(dir, "(unnamed)")), nil
	}

	return unlinkedTempFile(dir)
}
