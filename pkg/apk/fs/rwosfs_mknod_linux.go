// Copyright 2026 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux

package fs

import (
	"path"

	"golang.org/x/sys/unix"
)

// mknodOnDisk issues mknodat against a root-constrained parent directory FD
// so the syscall cannot be tricked into traversing a symlink out of the
// sandbox. If the underlying filesystem refuses the mode (e.g. tmpfs
// rejecting certain device types), a zero-byte placeholder is written
// through the root instead.
func (f *dirFS) mknodOnDisk(rel string, mode uint32, dev int) error {
	parent, err := f.root.Open(path.Dir(rel))
	if err != nil {
		return err
	}
	defer parent.Close()
	if err := unix.Mknodat(int(parent.Fd()), path.Base(rel), mode, dev); err == nil {
		return nil
	}
	return f.placeholderOnDisk(rel)
}
