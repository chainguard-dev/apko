// Copyright 2023 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package fs

import (
	"io"
	"io/fs"
)

// FullFS is a filesystem that supports all filesystem operations.
type FullFS interface {
	Mkdir(path string, perm fs.FileMode) error
	MkdirAll(path string, perm fs.FileMode) error
	Open(name string) (fs.File, error)
	OpenReaderAt(name string) (File, error)
	OpenFile(name string, flag int, perm fs.FileMode) (File, error)
	ReadFile(name string) ([]byte, error)
	WriteFile(name string, b []byte, mode fs.FileMode) error
	ReadDir(name string) ([]fs.DirEntry, error)
	Mknod(path string, mode uint32, dev int) error
	Readnod(name string) (dev int, err error)
	Symlink(oldname, newname string) error
	Link(oldname, newname string) error
	Readlink(name string) (target string, symlink bool, err error)
	Stat(path string) (fs.FileInfo, error)
	Lstat(path string) (fs.FileInfo, error)
	Create(name string) (File, error)
	Remove(name string) error
	Chmod(path string, perm fs.FileMode) error
	Chown(path string, uid int, gid int) error
}

// File is an interface for a file. It includes Read, Write, Close.
// This wouldn't be necessary if os.File were an interface, or if fs.File
// were read/write.
type File interface {
	fs.File
	io.WriteSeeker
	io.ReaderAt
}

type ReadLinkFS interface {
	fs.FS
	Readlink(name string) (string, bool, error)
}

type OpenReaderAtFS interface {
	fs.FS
	OpenReaderAt(name string) (File, error)
}

type ReadnodFS interface {
	fs.FS
	Readnod(name string) (dev int, err error)
}

type OpenReaderAtReadLinkFS interface {
	OpenReaderAtFS
	ReadLinkFS
}

type OpenReaderAtReadLinkReadnodFS interface {
	OpenReaderAtFS
	ReadLinkFS
	ReadnodFS
}
