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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func DirFS(dir string) FullFS {
	memfs := NewMemFS()
	m := memfs.(*memFS)
	f := &dirFS{
		base:      dir,
		overrides: m,
	}
	// need to populate the overrides with appropriate info
	root := os.DirFS(dir)

	_ = fs.WalkDir(root, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		mode := fi.Mode()
		perm := mode.Perm()
		switch mode.Type() {
		case fs.ModeDir:
			fullPerm := os.ModeDir | perm
			err = f.overrides.Mkdir(path, fullPerm)
		case fs.ModeSymlink:
			var target string
			target, err = os.Readlink(filepath.Join(dir, path))
			if err != nil {
				err = f.overrides.Symlink(target, path)
			}
		case fs.ModeCharDevice:
			var dev int
			sys := fi.Sys()
			st1, ok1 := sys.(*syscall.Stat_t)
			st2, ok2 := sys.(*unix.Stat_t)
			switch {
			case ok1:
				dev = int(st1.Rdev)
			case ok2:
				dev = int(st2.Rdev)
			default:
				return fmt.Errorf("unsupported type %T", sys)
			}
			err = f.overrides.Mknod(path, uint32(unix.S_IFCHR|mode), dev)
		default:
			var memFile File
			memFile, err = f.overrides.OpenFile(path, os.O_CREATE, perm)
			if memFile != nil {
				_ = memFile.Close()
			}
		}
		return err
	})

	return f
}

// dirFS represents a FullFS implementation based on a directory on disk.
// For those features that are not supported, e.g. activities that are non-permissioned
// or unsupported by the underlying filesystem or operating system, it keeps a separate map
// in memory.
type dirFS struct {
	base string
	// overrides is a map of overrides for things that could not be kept on disk because of permission,
	// filesystem or operating system limitations.
	// It will include all directories, but no file contents.
	// If there are permissions in memory, they override the disk.
	overrides *memFS
}

func (f *dirFS) Readlink(name string) (string, bool, error) {
	target, err := os.Readlink(filepath.Join(f.base, name))
	if err != nil {
		target, _, err = f.overrides.Readlink(name)
		if err != nil {
			return "", false, err
		}
	}
	return target, true, err
}

// Open open a file for reading. Returns fs.File.
// If the file has the wrong permissions for reading, it tries to
// change them, and then change them back when closing.
// This only works if the user reading the file actually has
// permissions to change the file permissions.
func (f *dirFS) Open(name string) (fs.File, error) {
	return f.open(name)
}

func (f *dirFS) open(name string) (*fileImpl, error) {
	fullpath, err := f.sanitizePath(name)
	if err != nil {
		return nil, err
	}
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

// Open open a file for reading. Returns fs.File.
// If the file has the wrong permissions for reading, it tries to
// change them, and then change them back when closing.
// This only works if the user reading the file actually has
// permissions to change the file permissions.
func (f *dirFS) OpenFile(name string, flag int, perm fs.FileMode) (File, error) {
	file, err := os.OpenFile(filepath.Join(f.base, name), flag, perm)
	if err != nil {
		return nil, err
	}
	// ensure it exists in memory, if it was open for create
	if flag&os.O_CREATE != 0 {
		memFile, err := f.overrides.OpenFile(name, flag, perm)
		if err != nil {
			return nil, err
		}
		_ = memFile.Close()
	}
	return file, nil
}

func (f *dirFS) OpenReaderAt(name string) (File, error) {
	return f.open(name)
}

func (f *dirFS) Stat(name string) (fs.FileInfo, error) {
	fi, err := os.Stat(filepath.Join(f.base, name))
	if err != nil {
		return nil, err
	}
	mi, err := f.overrides.Stat(name)
	if err != nil {
		return nil, err
	}
	return &fileInfo{
		file: fi,
		mem:  mi,
	}, nil
}
func (f *dirFS) Lstat(name string) (fs.FileInfo, error) {
	return f.overrides.Lstat(name)
}

func (f *dirFS) Create(name string) (File, error) {
	file, err := os.Create(filepath.Join(f.base, name))
	if err != nil {
		return nil, err
	}
	// ensure it exists in memory
	_, err = f.overrides.Create(name)
	return file, err
}

func (f *dirFS) Remove(name string) error {
	if err := os.Remove(filepath.Join(f.base, name)); err != nil {
		return err
	}
	return f.overrides.Remove(name)
}

func (f *dirFS) ReadDir(name string) ([]fs.DirEntry, error) {
	// get those on disk
	onDisk, err := os.ReadDir(filepath.Join(f.base, name))
	if err != nil {
		return nil, err
	}
	// should be identical in memory
	inMem, err := f.overrides.ReadDir(name)
	if err != nil {
		return nil, err
	}
	if len(onDisk) != len(inMem) {
		return nil, errors.New("mismatched entries in filesystems disk vs memory")
	}
	// merge them
	dirEntries := make([]fs.DirEntry, len(onDisk))
	for i, m := range inMem {
		f := onDisk[i]
		dirEntries[i] = &dirEntry{disk: f, mem: m}
	}
	return dirEntries, nil
}
func (f *dirFS) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(f.base, name))
}
func (f *dirFS) WriteFile(name string, b []byte, mode fs.FileMode) error {
	if err := os.WriteFile(filepath.Join(f.base, name), b, mode); err != nil {
		return err
	}
	// ensure file exists in memory, but with zero size
	return f.overrides.WriteFile(name, nil, mode)
}

func (f *dirFS) Readnod(name string) (dev int, err error) {
	_, err = os.Stat(filepath.Join(f.base, name))
	if err != nil {
		return 0, err
	}
	return f.overrides.Readnod(name)
}

func (f *dirFS) Link(oldname, newname string) error {
	// for hardlink, we cannot take target as is, as it might be outside of the base.
	// So we must sanitize it. It should point to a file that is within the filesystem.
	target := filepath.Join(f.base, oldname)
	target = filepath.Clean(target)
	if !strings.HasPrefix(target, f.base) {
		return fmt.Errorf("hardlink target %s is outside of the filesystem", target)
	}
	_ = os.Link(target, filepath.Join(f.base, newname))
	return f.overrides.Link(oldname, newname)
}

func (f *dirFS) Symlink(oldname, newname string) error {
	// For symlink, take target as is.
	// If it is outside of the base, it will be resolved by Readlink.
	// This enables proper symlink behaviour.
	_ = os.Symlink(oldname, filepath.Join(f.base, newname))
	return f.overrides.Symlink(oldname, newname)
}

func (f *dirFS) MkdirAll(name string, perm fs.FileMode) error {
	// just in case, because some underlying systems miss this
	fullPerm := os.ModeDir | perm
	if err := os.MkdirAll(filepath.Join(f.base, name), fullPerm); err != nil {
		return err
	}
	return f.overrides.MkdirAll(name, fullPerm)
}

func (f *dirFS) Mkdir(name string, perm fs.FileMode) error {
	// just in case, because some underlying systems miss this
	fullPerm := os.ModeDir | perm
	if err := os.Mkdir(filepath.Join(f.base, name), fullPerm); err != nil {
		return err
	}
	return f.overrides.Mkdir(name, fullPerm)
}

func (f *dirFS) Chmod(path string, perm fs.FileMode) error {
	_ = os.Chmod(filepath.Join(f.base, path), perm)
	return f.overrides.Chmod(path, perm)
}
func (f *dirFS) Chown(path string, uid int, gid int) error {
	_ = os.Chown(filepath.Join(f.base, path), uid, gid)
	return f.overrides.Chown(path, uid, gid)
}

func (f *dirFS) Mknod(name string, mode uint32, dev int) error {
	err := unix.Mknod(filepath.Join(f.base, name), mode, dev)
	// what if we could not create it? Just create a regular file there, and memory will override
	if err != nil {
		_ = os.WriteFile(filepath.Join(f.base, name), nil, 0)
	}
	return f.overrides.Mknod(name, mode, dev)
}

// sanitize ensures that we never go beyond the root of the filesystem
func (f *dirFS) sanitizePath(p string) (v string, err error) {
	return sanitizePath(f.base, p)
}
func sanitizePath(base, p string) (v string, err error) {
	v = filepath.Join(base, p)
	if strings.HasPrefix(filepath.Clean(v), base) {
		return v, nil
	}

	return "", fmt.Errorf("%s: %s", "content filepath is tainted", p)
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

type fileInfo struct {
	file fs.FileInfo
	mem  fs.FileInfo
}

func (f *fileInfo) Name() string {
	return f.file.Name()
}
func (f *fileInfo) Size() int64 {
	return f.file.Size()
}
func (f *fileInfo) Mode() fs.FileMode {
	return f.mem.Mode()
}
func (f *fileInfo) ModTime() time.Time {
	return f.file.ModTime()
}
func (f *fileInfo) IsDir() bool {
	return f.file.IsDir()
}
func (f *fileInfo) Sys() interface{} {
	return f.mem.Sys()
}

type dirEntry struct {
	disk fs.DirEntry
	mem  fs.DirEntry
}

func (d *dirEntry) Name() string {
	return d.disk.Name()
}

func (d *dirEntry) IsDir() bool {
	return d.disk.IsDir()
}

func (d *dirEntry) Type() fs.FileMode {
	return d.mem.Type()
}

func (d *dirEntry) Info() (fs.FileInfo, error) {
	diskInfo, err := d.disk.Info()
	if err != nil {
		return nil, err
	}
	memInfo, err := d.mem.Info()
	if err != nil {
		return nil, err
	}
	return &fileInfo{file: diskInfo, mem: memInfo}, nil
}
