// Copyright 2024 Chainguard, Inc.
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

package cpio

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/u-root/u-root/pkg/cpio"
)

func FromLayer(layer v1.Layer, dest io.Writer) error {
	// Open the filesystem layer to walk through the file.
	u, err := layer.Uncompressed()
	if err != nil {
		return err
	}
	defer u.Close()
	tarReader := tar.NewReader(u)

	w := cpio.NewDedupWriter(cpio.Newc.Writer(dest))

	// Iterate through the tar archive entries
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			fmt.Println("Error reading tar entry:", err)
			return err
		}

		// Determine CPIO file mode based on TAR typeflag
		switch header.Typeflag {
		case tar.TypeDir:
			if err := cpio.WriteRecordsAndDirs(w, []cpio.Record{
				cpio.Directory(header.Name, uint64(header.Mode)),
			}); err != nil {
				return err
			}

		case tar.TypeSymlink:
			if err := cpio.WriteRecordsAndDirs(w, []cpio.Record{
				cpio.Symlink(header.Name, header.Linkname),
			}); err != nil {
				return err
			}

		case tar.TypeReg:
			var original bytes.Buffer
			// TODO(mattmoor): Do something better here, but unfortunately the
			// cpio stuff wants a seekable reader, so coming from a tar reader
			// I'm not sure how much leeway we have to do something better
			// than buffering.
			//nolint:gosec
			if _, err := io.Copy(&original, tarReader); err != nil {
				fmt.Println("Error reading file content:", err)
				return err
			}

			if err := cpio.WriteRecordsAndDirs(w, []cpio.Record{
				cpio.StaticFile(header.Name, original.String(), uint64(header.Mode)),
			}); err != nil {
				return err
			}

		case tar.TypeChar:
			if err := cpio.WriteRecordsAndDirs(w, []cpio.Record{
				cpio.CharDev(header.Name, uint64(header.Mode), uint64(header.Devmajor), uint64(header.Devminor)),
			}); err != nil {
				return err
			}

		default:
			fmt.Printf("Unsupported TAR typeflag: %c for %s\n", header.Typeflag, header.Name)
			continue // Skip unsupported types
		}
	}

	return w.WriteRecord(cpio.TrailerRecord)
}
