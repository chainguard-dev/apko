// Copyright 2026 Chainguard, Inc.
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

package apk

import (
	"archive/tar"
	"io/fs"
	"os"

	"chainguard.dev/apko/pkg/apk/expandapk"
	"chainguard.dev/apko/pkg/apk/types"
)

// PackageContents is the per-package input to installation: the package's
// control-section metadata, its install records (tar headers, in install
// order), and a filesystem that opens each record's content by name. It
// abstracts the expanded APK so installation can be fed the same information
// from another carrier of it (e.g. a pre-indexed image of the package)
// without consulting the APK itself.
type PackageContents interface {
	// PkgInfo returns the package's parsed .PKGINFO.
	PkgInfo() (*types.PackageInfo, error)
	// ControlSection returns the package's control section exactly as
	// distributed — the compressed tar segment. This is the section's
	// identity-bearing form: its SHA1 is the checksum apk records for the
	// package.
	ControlSection() ([]byte, error)
	// ControlData returns the same section as the uncompressed tar stream,
	// which script and trigger extraction read. Carriers hold one form or
	// the other natively, and consumers need one or the other, so the
	// contract carries both rather than making every side convert.
	ControlData() ([]byte, error)
	// Size returns the package's total size in bytes, as recorded in the
	// installed database.
	Size() int64
	// Entries returns the package's install records in install order.
	Entries() ([]tar.Header, error)
	// FS opens an entry's content by its record name.
	FS() fs.FS
}

// ExpandedContents adapts an expanded APK to [PackageContents].
func ExpandedContents(exp *expandapk.APKExpanded) PackageContents {
	return expandedContents{exp}
}

type expandedContents struct {
	exp *expandapk.APKExpanded
}

func (e expandedContents) PkgInfo() (*types.PackageInfo, error) { return e.exp.PkgInfo() }
func (e expandedContents) ControlSection() ([]byte, error)      { return os.ReadFile(e.exp.ControlFile) }
func (e expandedContents) ControlData() ([]byte, error)         { return e.exp.ControlData() }
func (e expandedContents) Size() int64                          { return e.exp.Size }
func (e expandedContents) FS() fs.FS                            { return e.exp.TarFS }

func (e expandedContents) Entries() ([]tar.Header, error) {
	entries := e.exp.TarFS.Entries()
	headers := make([]tar.Header, 0, len(entries))
	for _, entry := range entries {
		headers = append(headers, entry.Header)
	}
	return headers, nil
}

// PackageData exposes the whole data section as a tar stream, which the
// non-WriteHeaderer install path consumes.
func (e expandedContents) PackageData() (*os.File, error) { return e.exp.PackageData() }
