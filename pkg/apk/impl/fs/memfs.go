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

package fs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/blang/vfs"
	origMemfs "github.com/blang/vfs/memfs"
	"golang.org/x/sys/unix"
)

const (
	linkFlagSymlink  = 's'
	linkFlagHardlink = 'h'
)

func NewMemFS() FullFS {
	return &memFS{origMemfs.Create()}
}

type memFS struct {
	*origMemfs.MemFS
}

func (m *memFS) MkdirAll(path string, perm fs.FileMode) error {
	// Fast path: if we can tell whether path is a directory or file, stop with success or error.
	dir, err := m.Stat(path)
	if err == nil {
		if dir.IsDir() {
			return nil
		}
		return &os.PathError{Op: "mkdir", Path: path, Err: errors.New("not a directory")}
	}

	// Slow path: make sure parent exists and then call Mkdir for path.
	i := len(path)
	for i > 0 && os.IsPathSeparator(path[i-1]) { // Skip trailing path separator.
		i--
	}

	j := i
	for j > 0 && !os.IsPathSeparator(path[j-1]) { // Scan backward over element.
		j--
	}

	if j > 1 {
		// Create parent.
		err = m.MkdirAll(path[:j-1], fs.ModeDir|perm)
		if err != nil {
			return err
		}
	}

	// Parent now exists; invoke Mkdir and use its result.
	err = m.Mkdir(path, fs.ModeDir|perm)
	if err != nil {
		// Handle arguments like "foo/." by
		// double-checking that directory doesn't exist.
		dir, err1 := m.Lstat(path)
		if err1 == nil && dir.IsDir() {
			return nil
		}
		return err
	}
	return nil
}

func (m *memFS) Open(name string) (fs.File, error) {
	return m.OpenFile(name, os.O_RDONLY, 0o644)
}

func (m *memFS) OpenFile(name string, flag int, perm fs.FileMode) (File, error) {
	// m.MemFS does not support symlinks, so we need to give it a resolved path.
	// That means walking through all of the parts until we get to the end, and
	// giving it the actual path to the file.
	truename, err := m.walkSymlinks(name)
	if err != nil {
		return nil, err
	}
	return m.openFile(truename, flag, perm)
}

// openFile opens a file, but assumes all symlinks in the interim path have been resolved.
func (m *memFS) openFile(name string, flag int, perm fs.FileMode) (*memFile, error) {
	f, err := m.MemFS.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return &memFile{f, m.MemFS}, nil
}

func (m *memFS) ReadFile(name string) ([]byte, error) {
	f, err := m.OpenFile(name, os.O_RDONLY, 0o644)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b := bytes.NewBuffer(nil)
	if _, err := io.Copy(b, f); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (m *memFS) WriteFile(name string, b []byte, mode fs.FileMode) error {
	f, err := m.OpenFile(name, os.O_RDWR|os.O_CREATE, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(f, bytes.NewBuffer(b)); err != nil {
		return err
	}
	return nil
}

func (m *memFS) ReadDir(name string) ([]fs.DirEntry, error) {
	fi, err := m.MemFS.ReadDir(name)
	if err != nil {
		return nil, err
	}
	var de = make([]fs.DirEntry, 0, len(fi))
	for _, f := range fi {
		de = append(de, fs.FileInfoToDirEntry(f))
	}
	return de, nil
}

func (m *memFS) OpenReaderAt(name string) (File, error) {
	return m.open(name)
}
func (m *memFS) open(name string) (*memFile, error) {
	f, err := m.MemFS.OpenFile(name, os.O_RDONLY, 0o644)
	if err != nil {
		return nil, err
	}
	return &memFile{File: f, fs: m.MemFS}, nil
}

func (m *memFS) Mknod(path string, mode uint32, dev int) error {
	file, err := m.OpenFile(
		path,
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC,
		fs.FileMode(mode)|os.ModeCharDevice|os.ModeDevice,
	)
	if err != nil {
		return err
	}
	defer file.Close()
	// save the major and minor numbers in the file itself
	devNumbers := []uint32{unix.Major(uint64(dev)), unix.Minor(uint64(dev))}
	return binary.Write(file, binary.LittleEndian, devNumbers)
}

func (m *memFS) Readnod(name string) (dev int, err error) {
	file, err := m.Open(name)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	fi, err := file.Stat()
	if err != nil {
		return 0, err
	}
	if fi.Mode()&os.ModeCharDevice != os.ModeCharDevice {
		return 0, fmt.Errorf("%s not a character device", name)
	}
	// read the major and minor numbers from the file itself
	devNumbers := make([]uint32, 2)
	if err := binary.Read(file, binary.LittleEndian, devNumbers); err != nil {
		return 0, err
	}
	return int(unix.Mkdev(devNumbers[0], devNumbers[1])), nil
}

func (m *memFS) Chmod(path string, perm fs.FileMode) error {
	return nil
}
func (m *memFS) Chown(path string, uid int, gid int) error {
	return nil
}
func (m *memFS) Create(name string) (File, error) {
	return m.OpenFile(name, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o666)
}

func (m *memFS) Symlink(oldname, newname string) error {
	return m.multilink(true, oldname, newname)
}
func (m *memFS) Link(oldname, newname string) error {
	return m.multilink(false, oldname, newname)
}
func (m *memFS) multilink(symlink bool, oldname, newname string) error {
	file, err := m.OpenFile(
		newname,
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC,
		0777|os.ModeSymlink)
	if err != nil {
		return err
	}
	defer file.Close()
	var linkType = linkFlagHardlink
	if symlink {
		linkType = linkFlagSymlink
	}
	// save the target in the file itself
	_, err = file.Write([]byte(fmt.Sprintf("%c:%s", linkType, oldname)))
	return err
}

func (m *memFS) Readlink(name string) (target string, symlink bool, err error) {
	truename, err := m.walkSymlinks(filepath.Dir(name))
	if err != nil {
		return "", false, err
	}
	return m.readLink(filepath.Join(truename, filepath.Base(name)))
}

// readLink reads the link target directly from the memfs.
func (m *memFS) readLink(name string) (string, bool, error) {
	file, err := m.openFile(name, os.O_RDONLY, 0o644)
	if err != nil {
		return "", false, err
	}
	defer file.Close()
	fi, err := file.Stat()
	if err != nil {
		return "", false, err
	}
	buf := make([]byte, fi.Size())
	if _, err = file.Read(buf); err != nil {
		return "", false, err
	}
	// first 2 bytes are the link type ("h" or "s") and a separator ":"
	if len(buf) < 3 {
		return "", false, fmt.Errorf("invalid link %s", name)
	}
	return string(buf[2:]), buf[0] == linkFlagSymlink, nil
}

func (m *memFS) walkSymlinks(path string) (string, error) {
	var final string
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		if seg == "" {
			continue
		}
		// see if this section exists; if it is not a symlink, just add it
		segmentName := filepath.Join(final, seg)
		fi, err := m.Stat(segmentName)
		// we can ignore the last segment not existing
		if err != nil {
			if i == len(segments)-1 {
				final = filepath.Join(final, seg)
				continue
			}
			return "", err
		}
		// not a symlink, so just append it
		if fi.Mode()&os.ModeSymlink != os.ModeSymlink {
			final = filepath.Join(final, seg)
		} else {
			// it is a symlink, so resolve it
			target, _, err := m.readLink(segmentName)
			// what if it was not found?
			switch {
			case err != nil && i != len(segments)-1:
				// we can handle the last one not existing, but no interim one
				return "", err
			case strings.HasPrefix(target, "/"):
				// was it an absolute path?
				final = target
			default:
				// relative path, so add it to the current path
				final = filepath.Join(final, target)
			}
		}
	}
	return final, nil
}

type memFile struct {
	vfs.File
	fs *origMemfs.MemFS
}

func (f *memFile) Stat() (fs.FileInfo, error) {
	return f.fs.Stat(f.Name())
}
