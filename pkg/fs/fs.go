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

package fs

import (
	"io/fs"
	"os"
)

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

func DirFS(dir string) OpenReaderAtReadLinkReadnodFS {
	return &readLinkNodFS{
		base: dir,
		f:    os.DirFS(dir),
	}
}
