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
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type memFS struct {
	tree *node
}

func NewMemFS() FullFS {
	return &memFS{
		tree: &node{
			dir:      true,
			children: map[string]*node{},
			name:     "/",
			mode:     fs.ModeDir | 0755,
		},
	}
}

// getNode returns the node for the given path. If the path is not found, it
// returns an error
func (m *memFS) getNode(path string) (*node, error) {
	if path == "/" || path == "." {
		return m.tree, nil
	}
	parent := filepath.Dir(path)
	parts := strings.Split(path, "/")
	node := m.tree
	for _, part := range parts {
		if part == "" {
			continue
		}
		if node.children == nil {
			return nil, os.ErrNotExist
		}
		var ok bool
		childNode, ok := node.children[part]
		if !ok {
			return nil, os.ErrNotExist
		}
		// what if it is a symlink?
		if childNode.mode&os.ModeSymlink != 0 {
			linkTarget := childNode.linkTarget
			if !filepath.IsAbs(linkTarget) {
				linkTarget = filepath.Join(parent, linkTarget)
			}
			targetNode, err := m.getNode(linkTarget)
			if err != nil {
				return nil, err
			}
			childNode = targetNode
		}
		node = childNode
	}
	return node, nil
}
func (m *memFS) Mkdir(path string, perms fs.FileMode) error {
	// first see if the parent exists
	parent := filepath.Dir(path)
	anode, err := m.getNode(parent)
	if err != nil {
		return err
	}
	if anode.mode&fs.ModeDir == 0 {
		return fmt.Errorf("parent is not a directory")
	}
	// see if it exists
	if _, ok := anode.children[filepath.Base(path)]; ok {
		return os.ErrExist
	}
	// now create the directory
	anode.children[filepath.Base(path)] = &node{
		name:       filepath.Base(path),
		mode:       fs.ModeDir | perms,
		dir:        true,
		modTime:    time.Now(),
		createTime: time.Now(),
		children:   map[string]*node{},
	}
	return nil
}

func (m *memFS) Stat(path string) (fs.FileInfo, error) {
	node, err := m.getNode(path)
	if err != nil {
		return nil, err
	}
	if node.mode&fs.ModeSymlink != 0 {
		targetNode, err := m.getNode(node.linkTarget)
		if err != nil {
			return nil, err
		}
		node = targetNode
	}
	return node.fileInfo(path), nil
}

func (m *memFS) Lstat(path string) (fs.FileInfo, error) {
	node, err := m.getNode(path)
	if err != nil {
		return nil, err
	}
	return node.fileInfo(path), nil
}

func (m *memFS) MkdirAll(path string, perm fs.FileMode) error {
	parts := strings.Split(path, "/")
	anode := m.tree
	for _, part := range parts {
		if part == "" {
			continue
		}
		if anode.children == nil {
			anode.children = map[string]*node{}
		}
		var ok bool
		newnode, ok := anode.children[part]
		if !ok {
			newnode = &node{
				name:       part,
				mode:       fs.ModeDir | perm,
				dir:        true,
				modTime:    time.Now(),
				createTime: time.Now(),
				children:   map[string]*node{},
			}
			anode.children[part] = newnode
			anode = newnode
			continue
		}
		// what if it is a symlink?
		if newnode.mode&os.ModeSymlink != 0 {
			targetNode, err := m.getNode(newnode.linkTarget)
			if err != nil {
				return err
			}
			newnode = targetNode
		}
		if !newnode.dir {
			return fmt.Errorf("path is not a directory")
		}
		anode = newnode
	}
	return nil
}

func (m *memFS) Open(name string) (fs.File, error) {
	return m.OpenFile(name, os.O_RDONLY, 0o644)
}

func (m *memFS) OpenFile(name string, flag int, perm fs.FileMode) (File, error) {
	parent := filepath.Dir(name)
	base := filepath.Base(name)
	parentAnode, err := m.getNode(parent)
	if err != nil {
		return nil, err
	}
	if !parentAnode.dir {
		return nil, fmt.Errorf("parent is not a directory")
	}
	if parentAnode.children == nil {
		parentAnode.children = map[string]*node{}
	}
	anode, ok := parentAnode.children[base]
	if !ok && flag&os.O_CREATE == 0 {
		return nil, os.ErrNotExist
	}
	if anode != nil && anode.dir {
		return nil, fmt.Errorf("is a directory")
	}
	if flag&os.O_CREATE != 0 && !ok {
		// create the file
		anode = &node{
			name:       base,
			mode:       perm,
			dir:        false,
			modTime:    time.Now(),
			createTime: time.Now(),
		}
		parentAnode.children[base] = anode
	}
	// what if it is a symlink? Follow the symlink
	if anode.mode&os.ModeSymlink != 0 {
		linkTarget := anode.linkTarget
		if !filepath.IsAbs(linkTarget) {
			linkTarget = filepath.Join(parent, linkTarget)
		}
		return m.OpenFile(linkTarget, flag, perm)
	}

	return newMemFile(anode, name, m, flag), nil
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
	f, err := m.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, mode)
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
	anode, err := m.getNode(name)
	if err != nil {
		return nil, err
	}
	if !anode.dir {
		return nil, fmt.Errorf("not a directory")
	}
	var de = make([]fs.DirEntry, 0, len(anode.children))
	for name, node := range anode.children {
		de = append(de, fs.FileInfoToDirEntry(node.fileInfo(name)))
	}
	return de, nil
}

func (m *memFS) OpenReaderAt(name string) (File, error) {
	return m.OpenFile(name, os.O_RDONLY, 0o644)
}

func (m *memFS) Mknod(path string, mode uint32, dev int) error {
	parent := filepath.Dir(path)
	base := filepath.Base(path)
	anode, err := m.getNode(parent)
	if err != nil {
		return err
	}
	if _, ok := anode.children[base]; ok {
		return os.ErrExist
	}
	anode.children[base] = &node{
		name:       base,
		mode:       fs.FileMode(mode) | os.ModeCharDevice | os.ModeDevice,
		modTime:    time.Now(),
		createTime: time.Now(),
		major:      unix.Major(uint64(dev)),
		minor:      unix.Minor(uint64(dev)),
	}

	return nil
}

func (m *memFS) Readnod(path string) (dev int, err error) {
	parent := filepath.Dir(path)
	base := filepath.Base(path)
	parentNode, err := m.getNode(parent)
	if err != nil {
		return 0, err
	}
	anode, ok := parentNode.children[base]
	if !ok {
		return 0, os.ErrNotExist
	}
	if anode.mode&os.ModeDevice != os.ModeDevice || anode.mode&os.ModeCharDevice != os.ModeCharDevice {
		return 0, fmt.Errorf("not a device")
	}
	return int(unix.Mkdev(anode.major, anode.minor)), nil
}

func (m *memFS) Chmod(path string, perm fs.FileMode) error {
	anode, err := m.getNode(path)
	if err != nil {
		return err
	}
	// need to change the mode, but keep the type
	anode.mode = perm | (anode.mode & os.ModeType)
	return nil
}
func (m *memFS) Chown(path string, uid int, gid int) error {
	anode, err := m.getNode(path)
	if err != nil {
		return err
	}
	anode.uid = uid
	anode.gid = gid
	return nil
}

func (m *memFS) Create(name string) (File, error) {
	return m.OpenFile(name, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o666)
}

func (m *memFS) Symlink(oldname, newname string) error {
	parent := filepath.Dir(newname)
	base := filepath.Base(newname)
	anode, err := m.getNode(parent)
	if err != nil {
		return err
	}
	if _, ok := anode.children[base]; ok {
		return os.ErrExist
	}
	anode.children[base] = &node{
		name:       base,
		mode:       0777 | os.ModeSymlink,
		modTime:    time.Now(),
		linkTarget: oldname,
	}
	return nil
}

func (m *memFS) Link(oldname, newname string) error {
	parent := filepath.Dir(newname)
	base := filepath.Base(newname)
	anode, err := m.getNode(parent)
	if err != nil {
		return err
	}
	if _, ok := anode.children[base]; ok {
		return os.ErrExist
	}
	target, err := m.getNode(oldname)
	if err != nil {
		return os.ErrNotExist
	}
	anode.children[base] = target
	target.linkCount++
	return nil
}

func (m *memFS) Readlink(name string) (target string, err error) {
	parent := filepath.Dir(name)
	base := filepath.Base(name)
	parentNode, err := m.getNode(parent)
	if err != nil {
		return "", err
	}
	anode, ok := parentNode.children[base]
	if !ok {
		return "", os.ErrNotExist
	}
	if anode.mode&os.ModeSymlink == 0 {
		return "", fmt.Errorf("file is not a link")
	}
	return anode.linkTarget, nil
}

func (m *memFS) Remove(name string) error {
	parent := filepath.Dir(name)
	base := filepath.Base(name)
	anode, err := m.getNode(parent)
	if err != nil {
		return err
	}
	if _, ok := anode.children[base]; !ok {
		return os.ErrNotExist
	}
	if anode.children[base].linkCount > 0 {
		anode.children[base].linkCount--
	}
	delete(anode.children, base)
	return nil
}

type memFile struct {
	node     *node
	fs       *memFS
	name     string
	offset   int64
	openMode int
}

func newMemFile(node *node, name string, fs *memFS, openMode int) *memFile {
	m := &memFile{
		node:     node,
		fs:       fs,
		name:     name,
		openMode: openMode,
	}
	if openMode&os.O_APPEND != 0 {
		m.offset = int64(len(node.data))
	}
	if openMode&os.O_TRUNC != 0 {
		node.data = nil
	}
	return m
}

func (f *memFile) Stat() (fs.FileInfo, error) {
	if f.node == nil || f.fs == nil {
		return nil, os.ErrClosed
	}
	return f.fs.Stat(f.name)
}

func (f *memFile) Close() error {
	if f.node == nil || f.fs == nil {
		return os.ErrClosed
	}
	f.fs = nil
	f.node = nil
	return nil
}

func (f *memFile) Read(b []byte) (int, error) {
	if f.node == nil || f.fs == nil {
		return 0, os.ErrClosed
	}
	if f.offset >= int64(len(f.node.data)) {
		return 0, io.EOF
	}
	n := copy(b, f.node.data[f.offset:])
	f.offset += int64(n)
	return n, nil
}

func (f *memFile) ReadAt(p []byte, off int64) (n int, err error) {
	if f.node == nil || f.fs == nil {
		return 0, os.ErrClosed
	}
	if off >= int64(len(f.node.data)) {
		return 0, io.EOF
	}
	n = copy(p, f.node.data[off:])
	return n, nil
}
func (f *memFile) Seek(offset int64, whence int) (int64, error) {
	if f.node == nil || f.fs == nil {
		return 0, os.ErrClosed
	}
	switch whence {
	case io.SeekStart:
		f.offset = offset
	case io.SeekCurrent:
		f.offset += offset
	case io.SeekEnd:
		f.offset = int64(len(f.node.data)) + offset
	default:
		return 0, errors.New("invalid whence")
	}
	return f.offset, nil
}

func (f *memFile) Write(p []byte) (n int, err error) {
	if f.node == nil || f.fs == nil {
		return 0, os.ErrClosed
	}
	if f.openMode&os.O_APPEND != 0 && f.openMode&os.O_RDWR != 0 && f.openMode&os.O_WRONLY != 0 {
		return 0, errors.New("file not opened in write mode")
	}
	if f.offset+int64(len(p)) > int64(len(f.node.data)) {
		f.node.data = append(f.node.data[:f.offset], p...)
	} else {
		copy(f.node.data[f.offset:], p)
	}
	f.offset += int64(len(p))
	return len(p), nil
}

type node struct {
	mode         fs.FileMode
	uid, gid     int
	dir          bool
	name         string
	data         []byte
	modTime      time.Time
	createTime   time.Time
	linkTarget   string
	linkCount    int // extra links, so 0 means a single pointer. O-based, like most compuuter counting systems.
	major, minor uint32
	children     map[string]*node
}

func (n *node) fileInfo(name string) fs.FileInfo {
	return &memFileInfo{
		node: n,
		name: name,
	}
}

type memFileInfo struct {
	*node
	name string
}

func (m *memFileInfo) Name() string {
	return m.name
}
func (m *memFileInfo) Size() int64 {
	return int64(len(m.data))
}
func (m *memFileInfo) Mode() fs.FileMode {
	return m.mode
}
func (m *memFileInfo) ModTime() time.Time {
	return m.modTime
}
func (m *memFileInfo) IsDir() bool {
	return m.dir
}
func (m *memFileInfo) Sys() any {
	return &tar.Header{
		Mode: int64(m.mode),
		Uid:  m.uid,
		Gid:  m.gid,
	}
}
