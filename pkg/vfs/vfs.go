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

package vfs

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// An INode contains overlay metadata for a filesystem entry that would
// otherwise be represented by a traditional inode on disk.
type INode struct {
	Filename      string
	Children      map[string]*INode
	UnderlayINode unix.Stat_t
}

// parseElements parses a path into components, and returns the current
// path component, followed by the remaining path components, and a hint
// as to whether or not the path list is terminated or not.
func parseElements(path string) (string, string, bool) {
	pathElements := strings.Split(path, "/")
	currentElement := pathElements[0]

	if len(pathElements) == 1 {
		return currentElement, "", true
	}

	otherElements := filepath.Join(pathElements[1:]...)
	if pathElements[0] == "." {
		currentElement = pathElements[1]
		otherElements = ""

		if len(pathElements) > 2 {
			otherElements = filepath.Join(pathElements[2:]...)
		}
	}

	return currentElement, otherElements, len(pathElements) == 1
}

func (i *INode) walk(path string) (*INode, error) {
	currentElement, otherElements, terminated := parseElements(path)

	// We are at the end of the path, return ourselves.
	if terminated {
		if currentElement == "" {
			return i, nil
		}

		if child, ok := i.Children[currentElement]; ok {
			return child, nil
		}

		return nil, fmt.Errorf("no underlay inode found")
	}

	// We are not at the end of the path, traverse downward.
	if child, ok := i.Children[currentElement]; ok {
		return child.walk(otherElements)
	}

	// We do not have any overlay INode.  Pass through to owning FS.
	return nil, fmt.Errorf("no underlay inode found")
}

// Stat looks up a child INode in the VFS or returns nothing.
// Note: We intentionally do not implement support for the `..` directory
// entry for security reasons.
func (i *INode) Stat(path string) (os.FileInfo, error) {
	child, err := i.walk(path)
	if err != nil {
		return INode{}, err
	}

	return *child, nil
}

// Create creates a new underlay INode.
func (i *INode) Create(path string) (*INode, error) {
	currentElement, otherElements, terminated := parseElements(path)

	// We are at the end of the path, return ourselves.
	if terminated {
		if child, ok := i.Children[currentElement]; ok {
			return child, nil
		}

		if i.Children == nil {
			i.Children = make(map[string]*INode)
		}

		child := &INode{Filename: currentElement}
		i.Children[currentElement] = child
		return child, nil
	}

	// We are not at the end of the path, traverse downward.
	if child, ok := i.Children[currentElement]; ok {
		return child.Create(otherElements)
	}

	// We do not yet have an overlay INode, create one and
	// continue downward.
	if i.Children == nil {
		i.Children = make(map[string]*INode)
	}

	child := &INode{Filename: currentElement}
	i.Children[currentElement] = child
	return child.Create(otherElements)
}

func (i *INode) walkOrCreate(path string) (*INode, error) {
	node, err := i.walk(path)
	if err != nil {
		// No overlay node, create a new one.
		node, err = i.Create(path)
		if err != nil {
			return nil, err
		}
	}

	return node, nil
}

// Chmod updates the permissions on an INode.
func (i *INode) Chmod(path string, mode fs.FileMode) error {
	node, err := i.walkOrCreate(path)
	if err != nil {
		return err
	}

	isDir := node.IsDir()
	newMode := mode

	if isDir {
		newMode |= fs.ModeDir
	}

	node.UnderlayINode.Mode = fileModeToStatMode(newMode)
	return nil
}

// Chown updates the ownership on an INode.
func (i *INode) Chown(path string, uid, gid uint32) error {
	node, err := i.walkOrCreate(path)
	if err != nil {
		return err
	}

	node.UnderlayINode.Uid = uid
	node.UnderlayINode.Gid = gid

	return nil
}

func (i INode) IsDir() bool {
	return i.Mode()&fs.ModeDir == fs.ModeDir
}

func (i INode) Mode() fs.FileMode {
	return fs.FileMode(i.UnderlayINode.Mode)
}

func (i INode) ModTime() time.Time {
	ts, tns := i.UnderlayINode.Mtim.Unix()
	return time.Unix(ts, tns)
}

func (i INode) Name() string {
	return i.Filename
}

func (i INode) Size() int64 {
	return i.UnderlayINode.Size
}

func (i INode) Sys() any {
	return &i.UnderlayINode
}

func (i INode) Info() (os.FileInfo, error) {
	return i, nil
}

func (i INode) Type() fs.FileMode {
	return i.Mode()
}

// BaseFS is the required interfaces for an underlay filesystem
// which is used with VFS.
type BaseFS interface {
	fs.FS
	fs.ReadDirFS
	fs.ReadFileFS
	fs.StatFS

	Create(path string) (io.WriteCloser, error)
	Remove(path string) error
	RemoveAll(path string) error
}

// VFS is an overlay virtual filesystem which tracks an underlying
// BaseFS.
//
// It allows for things like permission and ownership changes that
// do not require physical root access, because it is tracked at
// the VFS level instead.
type VFS struct {
	FS   BaseFS
	Root *INode
}

func (vfs *VFS) Stat(path string) (os.FileInfo, error) {
	inode, err := vfs.Root.Stat(path)
	if err == nil {
		return inode, err
	}

	return vfs.FS.Stat(path)
}

func (vfs *VFS) Create(path string) (io.WriteCloser, error) {
	return vfs.FS.Create(path)
}

func (vfs *VFS) Open(path string) (fs.File, error) {
	return vfs.FS.Open(path)
}

func (vfs *VFS) ReadFile(path string) ([]byte, error) {
	return vfs.FS.ReadFile(path)
}

func (vfs *VFS) ReadDir(path string) ([]fs.DirEntry, error) {
	de, err := vfs.FS.ReadDir(path)
	if err != nil {
		return []fs.DirEntry{}, err
	}

	baseINode, err := vfs.Root.walk(path)
	if err != nil {
		return de, nil
	}

	out := []fs.DirEntry{}
	for _, dentry := range de {
		if patchedINode, ok := baseINode.Children[dentry.Name()]; ok {
			out = append(out, patchedINode)
		} else {
			out = append(out, dentry)
		}
	}

	return out, nil
}

func (vfs *VFS) Chmod(path string, mode fs.FileMode) error {
	return vfs.Root.Chmod(path, mode)
}

func (vfs *VFS) Chown(path string, uid, gid uint32) error {
	return vfs.Root.Chown(path, uid, gid)
}

func New(base BaseFS) (*VFS, error) {
	return &VFS{
		FS: base,
		Root: &INode{
			Filename: ".",
		},
	}, nil
}
