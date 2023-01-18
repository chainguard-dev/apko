// Copyright 2022, 2023 Chainguard, Inc.
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

package fs

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

type readLinkNodFS struct {
	base string
	f    fs.FS
}

func (f *readLinkNodFS) Readlink(name string) (string, bool, error) {
	target, err := os.Readlink(filepath.Join(f.base, name))
	return target, true, err
}

// Open open a file for reading. Returns fs.File.
// If the file has the wrong permissions for reading, it tries to
// change them, and then change them back when closing.
// This only works if the user reading the file actually has
// permissions to change the file permissions.
func (f *readLinkNodFS) Open(name string) (fs.File, error) {
	return f.open(name)
}

func (f *readLinkNodFS) open(name string) (*fileImpl, error) {
	fullpath := filepath.Join(f.base, name)
	file, err := os.Open(fullpath)
	if err == nil {
		return &fileImpl{file, nil}, nil
	}
	if !os.IsPermission(err) {
		return nil, err
	}
	// get the original permissions
	fi, err := os.Stat(fullpath)
	if err != nil {
		return nil, fmt.Errorf("unable to stat file %s: %w", fullpath, err)
	}
	// Try to change permissions and open again.
	if err := os.Chmod(fullpath, 0600); err != nil {
		return nil, fmt.Errorf("unable to read file or change permissions: %s", name)
	}
	file, err = os.Open(fullpath)
	if err != nil {
		return nil, fmt.Errorf("unable to read file even after change permissions: %s", name)
	}
	perms := fi.Mode()
	return &fileImpl{file, &perms}, nil
}

func (f *readLinkNodFS) OpenReaderAt(name string) (File, error) {
	return f.open(name)
}

func (f *readLinkNodFS) Stat(name string) (fs.FileInfo, error) {
	return os.Stat(filepath.Join(f.base, name))
}

func (f *readLinkNodFS) Readnod(name string) (dev int, err error) {
	fi, err := os.Stat(filepath.Join(f.base, name))
	if err != nil {
		return 0, err
	}
	if fi.Mode()&os.ModeCharDevice != os.ModeCharDevice {
		return 0, fmt.Errorf("%s not a character device", name)
	}
	sys := fi.Sys()
	if statT, ok := sys.(*unix.Stat_t); ok {
		return int(statT.Dev), nil
	}
	if statT, ok := sys.(*syscall.Stat_t); ok {
		return int(statT.Dev), nil
	}

	return 0, fmt.Errorf("unable to cast to unix.Stat_t or syscall.Stat_t")
}

type File interface {
	fs.File
	io.ReaderAt
}
type fileImpl struct {
	*os.File
	perms *os.FileMode
}

func (f fileImpl) ReadAt(b []byte, off int64) (int, error) {
	return f.File.ReadAt(b, off)
}
func (f fileImpl) Close() error {
	if f.perms != nil {
		defer func() {
			_ = os.Chmod(f.Name(), *f.perms)
		}()
	}
	return f.File.Close()
}
