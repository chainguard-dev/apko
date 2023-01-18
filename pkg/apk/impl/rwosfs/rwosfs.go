// Copyright 2023 Chainguard, Inc.
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

package rwosfs

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	implfs "chainguard.dev/apko/pkg/apk/impl/rwfs"
)

type RWFS struct {
	root string
}

func NewReadWriteFS(root string) (*RWFS, error) {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	return &RWFS{root: root}, nil
}

func (f *RWFS) Open(path string) (fs.File, error) {
	v, err := f.sanitize(path)
	if err != nil {
		return nil, err
	}
	return os.Open(v)
}
func (f *RWFS) OpenFile(path string, flag int, perm fs.FileMode) (implfs.File, error) {
	v, err := f.sanitize(path)
	if err != nil {
		return nil, err
	}
	return os.OpenFile(v, flag, perm)
}
func (f *RWFS) Mkdir(path string, perm fs.FileMode) error {
	v, err := f.sanitize(path)
	if err != nil {
		return err
	}
	return os.Mkdir(v, perm)
}
func (f *RWFS) MkdirAll(path string, perm fs.FileMode) error {
	v, err := f.sanitize(path)
	if err != nil {
		return err
	}

	return os.MkdirAll(v, perm)
}
func (f *RWFS) WriteFile(path string, data []byte, perm fs.FileMode) error {
	v, err := f.sanitize(path)
	if err != nil {
		return err
	}
	return os.WriteFile(v, data, perm)
}
func (f *RWFS) ReadFile(path string) (data []byte, err error) {
	v, err := f.sanitize(path)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(v)
}
func (f *RWFS) ReadDir(path string) ([]fs.DirEntry, error) {
	v, err := f.sanitize(path)
	if err != nil {
		return nil, err
	}
	return os.ReadDir(v)
}
func (f *RWFS) Stat(path string) (fs.FileInfo, error) {
	v, err := f.sanitize(path)
	if err != nil {
		return nil, err
	}
	return os.Stat(v)
}
func (f *RWFS) Mknod(path string, mode uint32, dev int) error {
	v, err := f.sanitize(path)
	if err != nil {
		return err
	}
	return unix.Mknod(v, mode, dev)
}
func (f *RWFS) Symlink(oldname, path string) error {
	v, err := f.sanitize(path)
	if err != nil {
		return err
	}
	return os.Symlink(oldname, v)
}
func (f *RWFS) Link(oldname, path string) error {
	v, err := f.sanitize(path)
	if err != nil {
		return err
	}
	return os.Link(oldname, v)
}

// sanitize ensures that any path given is within the root of the filesystem.
func (f *RWFS) sanitize(path string) (string, error) {
	v := filepath.Join(f.root, path)
	clean := filepath.Clean(v)
	if strings.HasPrefix(clean, v) {
		return clean, nil
	}

	return "", fmt.Errorf("%s: %s", "content filepath is tainted", path)
}
