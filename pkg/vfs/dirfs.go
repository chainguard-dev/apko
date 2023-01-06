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
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

type dirFS string

// DirFS is a DirFS implementation that is suitable for use as a
// BaseFS.
func DirFS(path string) (BaseFS, error) {
	return dirFS(path), nil
}

func (dir dirFS) finalPath(path string) string {
	return filepath.Join(string(dir), path)
}

func (dir dirFS) Create(path string) (io.WriteCloser, error) {
	return os.Create(dir.finalPath(path))
}

func (dir dirFS) Open(path string) (fs.File, error) {
	return os.Open(dir.finalPath(path))
}

func (dir dirFS) ReadDir(path string) ([]fs.DirEntry, error) {
	return os.ReadDir(dir.finalPath(path))
}

func (dir dirFS) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(dir.finalPath(path))
}

func (dir dirFS) Stat(path string) (fs.FileInfo, error) {
	return os.Stat(dir.finalPath(path))
}

func (dir dirFS) Remove(path string) error {
	return os.Remove(dir.finalPath(path))
}

func (dir dirFS) RemoveAll(path string) error {
	return os.RemoveAll(dir.finalPath(path))
}
