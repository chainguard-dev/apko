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
	"errors"
	"fmt"
	"path"
	"strconv"

	"golang.org/x/sys/unix"
)

const procSelfFd = "/proc/self/fd"

// checkXattrsOnDisk reports whether xattrPath can work: it needs procfs.
func checkXattrsOnDisk() error {
	var st unix.Statfs_t
	if err := unix.Statfs(procSelfFd, &st); err != nil {
		return fmt.Errorf("%s: %w", procSelfFd, err)
	}
	if st.Type != unix.PROC_SUPER_MAGIC {
		return fmt.Errorf("%s is not on procfs", procSelfFd)
	}
	return nil
}

// xattrPath opens rel without following a final symlink and returns a
// /proc/self/fd path for it, plus a closer. The parent is opened through the
// root, so resolution cannot leave the sandbox. Both are opened O_PATH, so
// neither needs read permission and a device node is never actually opened. xattr syscalls do not accept an
// O_PATH fd directly, so they go through its /proc/self/fd magic link, which
// lands on the opened inode itself.
func (f *dirFS) xattrPath(rel string) (string, func(), error) {
	base := path.Base(rel)
	if base == ".." {
		return "", nil, fmt.Errorf("path %q escapes root", rel)
	}
	parent, err := f.root.OpenFile(path.Dir(rel), unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		return "", nil, err
	}
	defer parent.Close()
	fd, err := unix.Openat(int(parent.Fd()), base, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", nil, err
	}
	return procSelfFd + "/" + strconv.Itoa(fd), func() { _ = unix.Close(fd) }, nil
}

func (f *dirFS) setXattrOnDisk(rel, attr string, data []byte) error {
	p, closer, err := f.xattrPath(rel)
	if err != nil {
		return err
	}
	defer closer()
	return unix.Setxattr(p, attr, data, 0)
}

func (f *dirFS) removeXattrOnDisk(rel, attr string) error {
	p, closer, err := f.xattrPath(rel)
	if err != nil {
		return err
	}
	defer closer()
	if err := unix.Removexattr(p, attr); err != nil && !errors.Is(err, unix.ENODATA) {
		return err
	}
	return nil
}
