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

package rwfs

import (
	"io"
	"io/fs"
)

// FS is an interface for a filesystem. It includes fs.FS, as well as methods
// for writing to files. It extends fs.FS since the fs.FS interface only
// provides read-only.
type FS interface {
	fs.FS
	fs.ReadDirFS
	fs.StatFS
	fs.ReadFileFS
	OpenFile(name string, flag int, perm fs.FileMode) (File, error)
	Mkdir(string, fs.FileMode) error
	MkdirAll(string, fs.FileMode) error
	WriteFile(string, []byte, fs.FileMode) error
	Mknod(path string, mode uint32, dev int) error
	Symlink(oldname, newname string) error
	Link(oldname, newname string) error
}

// File is an interface for a file. It includes Read, Write, Close.
// This wouldn't be necessary if os.File were an interface, or if fs.File
// were read/write.
type File interface {
	fs.File
	io.WriteSeeker
}
