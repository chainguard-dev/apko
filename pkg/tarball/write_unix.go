// Copyright 2022, 2023 Chainguard, Inc.
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
// +build unix

package tarball

import (
	"fmt"
	"io/fs"
	"syscall"

	"golang.org/x/sys/unix"

	apkfs "chainguard.dev/apko/pkg/apk/impl/fs"
)

func hasHardlinks(fi fs.FileInfo) bool {
	if stat := fi.Sys(); stat != nil {
		si, ok := stat.(*syscall.Stat_t)
		if !ok {
			return false
		}

		// if we don't have inodes, we just assume the filesystem
		// does not support hardlinks
		if si == nil {
			return false
		}

		return si.Nlink > 1
	}

	return false
}

func getInodeFromFileInfo(fi fs.FileInfo) (uint64, error) {
	if stat := fi.Sys(); stat != nil {
		si := stat.(*syscall.Stat_t)

		// if we don't have inodes, we just assume the filesystem
		// does not support hardlinks
		if si == nil {
			return 0, fmt.Errorf("unable to stat underlying file")
		}

		return si.Ino, nil
	}

	return 0, fmt.Errorf("unable to stat underlying file")
}

func (ctx *Context) charDevice(path string, fsys fs.FS, info fs.FileInfo) (isCharDevice bool, major, minor uint32, _ error) {
	rlfs, ok := fsys.(apkfs.ReadnodFS)
	if !ok {
		return false, 0, 0, fmt.Errorf("read character device not supported by this fs: path (%s) %#v %#v", path, info, fsys)
	}
	dev, err := rlfs.Readnod(path)
	if err != nil {
		return false, 0, 0, err
	}
	major = unix.Major(uint64(dev))
	minor = unix.Minor(uint64(dev))

	return true, major, minor, nil
}
