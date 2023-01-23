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

package idb

import (
	"fmt"
	"path/filepath"

	apkfs "chainguard.dev/apko/pkg/apk/impl/fs"
	"chainguard.dev/apko/pkg/sbom/options"
)

// IDB treats the APK installed DB as an SBOM, which can be used with
// `apk audit` to check an image for runtime deviations.
type IDB struct {
	fs apkfs.FullFS
}

func New(fs apkfs.FullFS) IDB {
	return IDB{fs}
}

func (i *IDB) Key() string {
	return "idb"
}

func (i *IDB) Ext() string {
	return "idb"
}

// Generate copies the IDB from the work directory and saves it as
// an SBOM.
func (i *IDB) Generate(opts *options.Options, path string) error {
	idbPath := filepath.Join("lib", "apk", "db", "installed")

	idbData, err := i.fs.ReadFile(idbPath)
	if err != nil {
		return fmt.Errorf("reading installed db for copying: %w", err)
	}

	if err := i.fs.WriteFile(path, idbData, 0o600); err != nil {
		return fmt.Errorf("copying installed db: %w", err)
	}

	return nil
}

func (i *IDB) GenerateIndex(opts *options.Options, path string) error {
	return nil
}
