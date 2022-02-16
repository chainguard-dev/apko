// Copyright 2022 Chainguard, Inc.
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

package tarball

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"io/fs"
	"os"

	"github.com/pkg/errors"
)

// Writes a raw TAR archive to out, given an fs.FS.
func WriteArchiveFromFS(fsys fs.FS, out io.Writer) error {
	gzw := gzip.NewWriter(out)
	defer gzw.Close()

	tw := tar.NewWriter(gzw)
	defer tw.Close()

	fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		info, err := d.Info()
		if err != nil {
			return err
		}

		header, err := tar.FileInfoHeader(info, path)
		if err != nil {
			return err
		}

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		if !info.IsDir() {
			data, err := fsys.Open(path)
			if err != nil {
				return err
			}

			if _, err := io.Copy(tw, data); err != nil {
				return err
			}
		}

		return nil
	})

	return nil
}

// Writes a tarball to a temporary file.  Caller's responsibility to
// clean it up when it's done with it.
func WriteTarball(src string) (string, error) {
	outfile, err := os.CreateTemp("", "apko-*.tar.gz")
	if err != nil {
		return "", errors.Wrap(err, "opening a temporary file failed")
	}
	defer outfile.Close()

	fs := os.DirFS(src)
	err = WriteArchiveFromFS(fs, outfile)
	if err != nil {
		return "", errors.Wrap(err, "writing TAR archive failed")
	}

	filename := outfile.Name()
	return filename, nil
}
