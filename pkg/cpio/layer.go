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
	"math"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/u-root/u-root/pkg/cpio"
)

// FromLayer converts a container layer to CPIO format.
func FromLayer(layer v1.Layer, dest io.Writer) error {
	return FromLayers([]v1.Layer{layer}, dest)
}

// FromLayers converts multiple container layers to a single CPIO archive.
func FromLayers(layers []v1.Layer, dest io.Writer) error {
	w := cpio.NewDedupWriter(cpio.Newc.Writer(dest))

	for _, layer := range layers {
		if err := recordsFromLayer(layer, w); err != nil {
			return err
		}
	}

	return w.WriteRecord(cpio.TrailerRecord)
}

// preserveOwnership copies numeric UID/GID from a TAR header onto a CPIO
// record. newc stores ownership in 32-bit fields, so values outside that
// range are rejected rather than truncated.
func preserveOwnership(rec cpio.Record, hdr *tar.Header) (cpio.Record, error) {
	if hdr.Uid < 0 || hdr.Gid < 0 {
		return cpio.Record{}, fmt.Errorf("negative uid/gid on %q: %d:%d",
			hdr.Name, hdr.Uid, hdr.Gid)
	}
	if uint64(hdr.Uid) > math.MaxUint32 || uint64(hdr.Gid) > math.MaxUint32 {
		return cpio.Record{}, fmt.Errorf("uid/gid outside newc range on %q: %d:%d",
			hdr.Name, hdr.Uid, hdr.Gid)
	}
	rec.UID = uint64(hdr.Uid)
	rec.GID = uint64(hdr.Gid)
	return rec, nil
}

func writeRecord(w cpio.RecordWriter, rec cpio.Record, hdr *tar.Header) error {
	rec, err := preserveOwnership(rec, hdr)
	if err != nil {
		return err
	}
	return cpio.WriteRecordsAndDirs(w, []cpio.Record{rec})
}

// recordsFromLayer reads tar entries from a layer and writes them as CPIO records.
func recordsFromLayer(layer v1.Layer, w cpio.RecordWriter) error {
	// Open the filesystem layer to walk through the file.
	u, err := layer.Uncompressed()
	if err != nil {
		return err
	}
	defer u.Close()

	tarReader := tar.NewReader(u)

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
			if err := writeRecord(w, cpio.Directory(header.Name, uint64(header.Mode)), header); err != nil {
				return err
			}

		case tar.TypeSymlink:
			if err := writeRecord(w, cpio.Symlink(header.Name, header.Linkname), header); err != nil {
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

			if err := writeRecord(w, cpio.StaticFile(header.Name, original.String(), uint64(header.Mode)), header); err != nil {
				return err
			}

		case tar.TypeChar:
			if err := writeRecord(w, cpio.CharDev(header.Name, uint64(header.Mode), uint64(header.Devmajor), uint64(header.Devminor)), header); err != nil {
				return err
			}

		default:
			fmt.Printf("Unsupported TAR typeflag: %c for %s\n", header.Typeflag, header.Name)
			continue // Skip unsupported types
		}
	}

	return nil
}
