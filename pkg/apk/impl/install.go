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

package impl

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
)

// writeOneFile writes one file from the APK given the tar header and tar reader.
func (a *APKImplementation) writeOneFile(header *tar.Header, tr *tar.Reader) error {
	f, err := a.fs.OpenFile(header.Name, os.O_CREATE|os.O_WRONLY, header.FileInfo().Mode().Perm())
	if err != nil {
		return fmt.Errorf("error creating file %s: %w", header.Name, err)
	}
	defer f.Close()

	if _, err := io.CopyN(f, tr, header.Size); err != nil {
		return fmt.Errorf("unable to write content for %s: %w", header.Name, err)
	}

	return nil
}

// installAPKFiles install the files from the APK and return the list of installed files
// and their permissions. Returns a tar.Header because it is a convenient existing
// struct that has all of the fields we need.
func (a *APKImplementation) installAPKFiles(gzipIn io.Reader) ([]tar.Header, error) {
	var files []tar.Header
	gr, err := gzip.NewReader(gzipIn)
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gr)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			// special case, if the target already exists, and it is a symlink to a directory, we can accept it as is
			// otherwise, we need to create the directory.
			if fi, err := a.fs.Stat(header.Name); err == nil && fi.Mode()&os.ModeSymlink != 0 {
				if target, symlink, err := a.fs.Readlink(header.Name); err == nil && symlink {
					if fi, err = a.fs.Stat(target); err == nil && fi.IsDir() {
						continue
					}
				}
			}
			if err := a.fs.MkdirAll(header.Name, header.FileInfo().Mode().Perm()); err != nil {
				return nil, fmt.Errorf("error creating directory %s: %w", header.Name, err)
			}
		case tar.TypeReg:
			if err := a.writeOneFile(header, tr); err != nil {
				return nil, err
			}
		case tar.TypeSymlink:
			// some underlying filesystems and some memfs that we use in tests do not support symlinks.
			// attempt it, and if it fails, just copy it.
			if err := a.fs.Symlink(header.Linkname, header.Name); err != nil {
				return nil, err
			}
		case tar.TypeLink:
			if err := a.fs.Link(header.Linkname, header.Name); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unsupported file type %v", header.Typeflag)
		}
		files = append(files, *header)
	}

	return files, nil
}
