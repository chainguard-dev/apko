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
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type dirFSOpts struct {
	caseSensitive    bool
	caseSensitiveSet bool
	mkdir            bool
}

// DirFSOption is an option for DirFS
type DirFSOption func(*dirFSOpts) error

// DirFSWithCaseSensitive allows you to specify whether the underlying filesystem
// should be treated as case-sensitive or insensitive. If you do not specify this,
// it determines it by testing the underlying filesystem.
// Normally you should let the filesystem determine this, but sometimes this can be useful.
func DirFSWithCaseSensitive(caseSensitive bool) DirFSOption {
	return func(opts *dirFSOpts) error {
		opts.caseSensitive = caseSensitive
		opts.caseSensitiveSet = true
		return nil
	}
}

// WithCreateDir allows you to specify whether the underlying directory
// should be created if it does not exist. Default is false.
func WithCreateDir(createDir bool) DirFSOption {
	return func(opts *dirFSOpts) error {
		opts.mkdir = true
		return nil
	}
}

func DirFS(dir string, opts ...DirFSOption) FullFS {
	var options dirFSOpts
	for _, opt := range opts {
		if err := opt(&options); err != nil {
			return nil
		}
	}

	memfs := NewMemFS()
	m := memfs.(*memFS)

	// check if the underlying filesystem is case-sensitive
	fi, err := os.Stat(dir)
	switch {
	case err != nil && !os.IsNotExist(err):
		return nil
	case err != nil && os.IsNotExist(err):
		if !options.mkdir {
			return nil
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil
		}
	case !fi.IsDir():
		return nil
	}

	var caseSensitive bool
	if options.caseSensitiveSet {
		caseSensitive = options.caseSensitive
	} else {
		// check if the underlying filesystem is case-sensitive
		// we cannot just use it in TempDir() because these might be different filesystems
		// find a file that does not exist
		for i := 0; ; i++ {
			filename := fmt.Sprintf("test-dirfs-%d", i)
			if _, err := os.Stat(filepath.Join(dir, filename)); err == nil {
				continue
			}
			if err := os.WriteFile(filepath.Join(dir, filename), []byte("test"), 0o600); err != nil {
				return nil
			}
			// see if it exists
			if _, err := os.Stat(filepath.Join(dir, strings.ToUpper(filename))); err != nil {
				caseSensitive = true
			}
			// clean up our own messes
			_ = os.Remove(filepath.Join(dir, filename))
			break
		}
	}

	var caseMap map[string]string
	if !caseSensitive {
		caseMap = map[string]string{}
	}
	f := &dirFS{
		base:      dir,
		overrides: m,
		caseMap:   caseMap,
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
//
// How case-sensitivity works.
// If the underlying filesystem is case-sensitive, then all files are mapped both on disk and in memory,
// with content solely on disk to save space.
// If the underlying filesystem is case-insensitive, then we can only have one variant of each file on disk,
// but multiple in memory. Each file provided is converted to lower-case. That is then used as a key
// in a map, whose value is the one that is on disk. Any other variant is in memory.
// If the case-sensitive filename you are looking for is the same as the value in the map, it is on disk,
// else in memory.
type dirFS struct {
	base string
	// overrides is a map of overrides for things that could not be kept on disk because of permission,
	// filesystem or operating system limitations.
	// It will include all directories, but no file contents.
	// If there are permissions in memory, they override the disk.
	overrides *memFS
	// caseMap if non-nil, underlying filesystem is case-insensitive, so only one variant of each file
	// can exist on disk. Maps the case-sensitive to the case-insensitive variant
	caseMap      map[string]string
	caseMapMutex sync.Mutex
}

func (f *dirFS) Readlink(name string) (string, bool, error) {
	// The underlying filesystem might not support symlinks, and it might be case-insensitive, so just
	// use the one in memory.
	target, isSymlink, err := f.overrides.Readlink(name)
	if err != nil {
		return "", false, err
	}
	return target, isSymlink, err
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
	baseName := filepath.Base(name)
	if f.caseSensitiveOnDisk(name) {
		file, err := os.Open(fullpath)
		if err == nil {
			return &fileImpl{
				file: file,
				name: baseName,
			}, nil
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
		return &fileImpl{
			file:  file,
			name:  baseName,
			perms: &perms,
		}, nil
	}

	file, err := f.overrides.OpenReaderAt(name)
	if err != nil {
		return nil, err
	}
	return &fileImpl{file: file, name: baseName}, nil
}

// Open open a file for reading. Returns fs.File.
// If the file has the wrong permissions for reading, it tries to
// change them, and then change them back when closing.
// This only works if the user reading the file actually has
// permissions to change the file permissions.
func (f *dirFS) OpenFile(name string, flag int, perm fs.FileMode) (File, error) {
	var (
		file File
		err  error
	)
	if flag&os.O_CREATE == os.O_CREATE {
		file, err = f.overrides.OpenFile(name, flag, perm)
		if err != nil {
			return nil, err
		}
		// do we create it on disk?
		if f.createOnDisk(name) {
			_ = file.Close()
			file, err = os.OpenFile(filepath.Join(f.base, name), flag, perm)
			if err != nil {
				return nil, err
			}
		}
	} else {
		if f.caseSensitiveOnDisk(name) {
			file, err = os.OpenFile(filepath.Join(f.base, name), flag, perm)
		} else {
			file, err = f.overrides.OpenFile(name, flag, perm)
		}
		if err != nil {
			return nil, err
		}
	}
	return file, nil
}

func (f *dirFS) OpenReaderAt(name string) (File, error) {
	return f.open(name)
}

func (f *dirFS) Stat(name string) (fs.FileInfo, error) {
	var (
		fi  fs.FileInfo
		err error
	)
	mi, err := f.overrides.Stat(name)
	if err != nil {
		return nil, err
	}
	if f.caseSensitiveOnDisk(name) {
		fi, err = os.Stat(filepath.Join(f.base, name))
		if err != nil {
			return nil, err
		}
	} else {
		fi = mi
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
	// if the underlying filesystem is case-insensitive, check if the file exists and, if so,
	// do it only in memory.
	var (
		file File
		err  error
	)
	file, err = f.overrides.Create(name)
	if err != nil {
		return nil, err
	}
	// do we create it on disk?
	if f.createOnDisk(name) {
		// close the memory one
		_ = file.Close()
		file, err = os.Create(filepath.Join(f.base, name))
		if err != nil {
			return nil, err
		}
	}

	return file, err
}

func (f *dirFS) Remove(name string) error {
	if err := f.overrides.Remove(name); err != nil {
		return err
	}
	if f.removeOnDisk(name) {
		return os.Remove(filepath.Join(f.base, name))
	}
	return nil
}

func (f *dirFS) ReadDir(name string) ([]fs.DirEntry, error) {
	// get those on disk
	var (
		onDisk, inMem []fs.DirEntry
		err           error
	)
	if f.caseSensitiveOnDisk(name) {
		onDisk, err = os.ReadDir(filepath.Join(f.base, name))
		if err != nil {
			return nil, err
		}
	}
	// get those in memory
	inMem, err = f.overrides.ReadDir(name)
	if err != nil {
		return nil, err
	}
	// possibilities:
	// - directory on disk is case-insensitive and not the unique one: no entries on disk
	// - directory on disk is case-insensitive and the unique one: disk entries and memory entries; all disk must be in mem, but mem may have more
	// - directory on disk is case-sensitive: disk entries and memory entries; all disk must be in mem, but mem may have more
	//
	// either way, memory always should be >= disk
	diskEntries := make(map[string]fs.DirEntry, len(onDisk))
	for _, d := range onDisk {
		diskEntries[d.Name()] = d
	}

	dirEntries := make([]fs.DirEntry, 0, len(inMem))
	for _, m := range inMem {
		f := m
		if d, ok := diskEntries[m.Name()]; ok {
			f = d
		}
		dirEntries = append(dirEntries, &dirEntry{disk: f, mem: m})
	}
	return dirEntries, nil
}
func (f *dirFS) ReadFile(name string) ([]byte, error) {
	if f.caseSensitiveOnDisk(name) {
		return os.ReadFile(filepath.Join(f.base, name))
	}
	return f.overrides.ReadFile(name)
}
func (f *dirFS) WriteFile(name string, b []byte, mode fs.FileMode) error {
	var (
		memContent []byte
	)
	if f.createOnDisk(name) {
		if err := os.WriteFile(filepath.Join(f.base, name), b, mode); err != nil {
			return err
		}
	} else {
		memContent = b
	}

	// ensure file exists in memory
	// if this is just a flag for what is on disk, make it with zero size
	// if it is the actual file because of case sensitivity, then use the actual content
	return f.overrides.WriteFile(name, memContent, mode)
}

func (f *dirFS) Readnod(name string) (dev int, err error) {
	if f.caseSensitiveOnDisk(name) {
		_, err = os.Stat(filepath.Join(f.base, name))
		if err != nil {
			return 0, err
		}
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
	if f.createOnDisk(newname) {
		_ = os.Link(target, filepath.Join(f.base, newname))
	}
	return f.overrides.Link(oldname, newname)
}

func (f *dirFS) Symlink(oldname, newname string) error {
	// For symlink, take target as is.
	// If it is outside of the base, it will be resolved by Readlink.
	// This enables proper symlink behaviour.
	if f.createOnDisk(newname) {
		_ = os.Symlink(oldname, filepath.Join(f.base, newname))
	}
	return f.overrides.Symlink(oldname, newname)
}

func (f *dirFS) MkdirAll(name string, perm fs.FileMode) error {
	// just in case, because some underlying systems miss this
	fullPerm := os.ModeDir | perm
	if f.createOnDisk(name) {
		if err := os.MkdirAll(filepath.Join(f.base, name), fullPerm); err != nil {
			return err
		}
	}
	return f.overrides.MkdirAll(name, fullPerm)
}

func (f *dirFS) Mkdir(name string, perm fs.FileMode) error {
	// just in case, because some underlying systems miss this
	fullPerm := os.ModeDir | perm
	if f.createOnDisk(name) {
		if err := os.Mkdir(filepath.Join(f.base, name), fullPerm); err != nil {
			return err
		}
	}
	return f.overrides.Mkdir(name, fullPerm)
}

func (f *dirFS) Chmod(path string, perm fs.FileMode) error {
	if f.caseSensitiveOnDisk(path) {
		// ignore error, as we track it in memory anyways, and disk filesystem might not support it
		_ = os.Chmod(filepath.Join(f.base, path), perm)
	}
	return f.overrides.Chmod(path, perm)
}
func (f *dirFS) Chown(path string, uid int, gid int) error {
	if f.caseSensitiveOnDisk(path) {
		// ignore error, as we track it in memory anyways, and disk filesystem might not support it
		_ = os.Chown(filepath.Join(f.base, path), uid, gid)
	}
	return f.overrides.Chown(path, uid, gid)
}

func (f *dirFS) Mknod(name string, mode uint32, dev int) error {
	if f.caseSensitiveOnDisk(name) {
		err := unix.Mknod(filepath.Join(f.base, name), mode, dev)
		// what if we could not create it? Just create a regular file there, and memory will override
		if err != nil {
			_ = os.WriteFile(filepath.Join(f.base, name), nil, 0)
		}
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

func (f *dirFS) caseSensitiveOnDisk(p string) bool {
	if f.caseMap == nil {
		return true
	}
	f.caseMapMutex.Lock()
	defer f.caseMapMutex.Unlock()
	p = standardizePath(p)
	key := strings.ToLower(p)
	result, ok := f.caseMap[key]
	if !ok {
		return true
	}
	return result == p
}

// createOnDisk given a path p, determine if it should be created on disk, and, if relevant,
// add it to the caseMap. If the file already exists on disk, also returns true.
// This func is responsible solely for determining if you _should_ created it on disk.
// If that would cause a conflict, that is up to the calling routing to figure out.
func (f *dirFS) createOnDisk(p string) bool {
	if f.caseMap == nil {
		return true
	}
	f.caseMapMutex.Lock()
	defer f.caseMapMutex.Unlock()
	p = standardizePath(p)
	key := strings.ToLower(p)
	result, ok := f.caseMap[key]
	if !ok {
		f.caseMap[key] = p
		return true
	}
	return result == p
}

// removeOnDisk given a path p, determine if it should be removed from disk, and, if relevant,
// remove it from the caseMap.
func (f *dirFS) removeOnDisk(p string) (removeOnDisk bool) {
	f.caseMapMutex.Lock()
	defer f.caseMapMutex.Unlock()
	key := strings.ToLower(p)
	if f.caseMap == nil {
		removeOnDisk = true
	} else if v, ok := f.caseMap[key]; ok && v == p {
		delete(f.caseMap, key)
		removeOnDisk = true
	}
	return
}

type file File
type fileImpl struct {
	file
	name  string
	perms *os.FileMode
}

func (f fileImpl) Close() error {
	if f.perms != nil {
		defer func() {
			_ = os.Chmod(f.name, *f.perms)
		}()
	}
	return f.file.Close()
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
