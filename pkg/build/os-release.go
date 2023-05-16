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

package build

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	apkfs "github.com/chainguard-dev/go-apk/pkg/fs"

	"chainguard.dev/apko/pkg/build/types"
)

func maybeGenerateVendorReleaseFile(fsys apkfs.FullFS, osr types.OSRelease) error {
	if osr.ID == "" || osr.VersionID == "" {
		return nil
	}

	path := filepath.Join("etc", fmt.Sprintf("%s-release", osr.ID))

	_, err := fsys.Stat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	w, err := fsys.Create(path)
	if err != nil {
		return err
	}
	defer w.Close()

	_, err = fmt.Fprintf(w, "%s\n", osr.VersionID)
	if err != nil {
		return err
	}

	return nil
}

func (bc *Context) GenerateOSRelease() error {
	path := filepath.Join("etc", "os-release")

	osReleaseExists := true
	if _, err := bc.fs.Stat(path); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		bc.Logger().Warnf("did not find /etc/os-release at %s", path)
		osReleaseExists = false
	}

	osr := bc.ImageConfiguration.OSRelease

	// If /etc/os-release does not exist, return an error that it already exists.
	// However, if the user is requesting an override, write over it anyway.
	// TODO: better than checking for "apko-generated image"
	if osReleaseExists && osr.Name == "apko-generated image" {
		return ErrOSReleaseAlreadyPresent
	}

	w, err := bc.fs.Create(path)
	if err != nil {
		return err
	}
	defer w.Close()

	if osr.ID != "" {
		if osr.ID == "unknown" {
			bc.Logger().Warnf("distro ID not specified and /etc/os-release does not already exist")
		}
		_, err := fmt.Fprintf(w, "ID=%s\n", osr.ID)
		if err != nil {
			return err
		}
	}

	if osr.Name != "" {
		_, err := fmt.Fprintf(w, "NAME=\"%s\"\n", osr.Name)
		if err != nil {
			return err
		}
	}

	if osr.PrettyName != "" {
		_, err := fmt.Fprintf(w, "PRETTY_NAME=\"%s\"\n", osr.PrettyName)
		if err != nil {
			return err
		}
	}

	if osr.VersionID != "" {
		_, err := fmt.Fprintf(w, "VERSION_ID=%s\n", osr.VersionID)
		if err != nil {
			return err
		}
	}

	if osr.HomeURL != "" {
		_, err := fmt.Fprintf(w, "HOME_URL=\"%s\"\n", osr.HomeURL)
		if err != nil {
			return err
		}
	}

	if osr.BugReportURL != "" {
		_, err := fmt.Fprintf(w, "BUG_REPORT_URL=\"%s\"\n", osr.BugReportURL)
		if err != nil {
			return err
		}
	}

	if err := maybeGenerateVendorReleaseFile(bc.fs, bc.ImageConfiguration.OSRelease); err != nil {
		return err
	}

	return nil
}
