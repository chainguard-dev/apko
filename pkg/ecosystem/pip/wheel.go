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

package pip

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
)

// extractWheel extracts a wheel (.whl) file into the filesystem at the given
// site-packages path. A .whl file is a ZIP archive.
func extractWheel(fsys apkfs.FullFS, wheelData []byte, sitePackagesPath string) error {
	reader, err := zip.NewReader(bytes.NewReader(wheelData), int64(len(wheelData)))
	if err != nil {
		return fmt.Errorf("opening wheel as zip: %w", err)
	}

	for _, f := range reader.File {
		targetPath := filepath.Join(sitePackagesPath, f.Name)

		if f.FileInfo().IsDir() {
			if err := fsys.MkdirAll(targetPath, 0755); err != nil {
				return fmt.Errorf("creating directory %s: %w", targetPath, err)
			}
			continue
		}

		// Ensure parent directory exists
		dir := filepath.Dir(targetPath)
		if err := fsys.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("creating parent directory %s: %w", dir, err)
		}

		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("opening %s in wheel: %w", f.Name, err)
		}

		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return fmt.Errorf("reading %s from wheel: %w", f.Name, err)
		}

		if err := fsys.WriteFile(targetPath, data, 0644); err != nil {
			return fmt.Errorf("writing %s: %w", targetPath, err)
		}
	}

	return nil
}

// writeInstallerFile writes the PEP 376 INSTALLER file into the .dist-info directory.
func writeInstallerFile(fsys apkfs.FullFS, sitePackagesPath string, wheelData []byte) error {
	reader, err := zip.NewReader(bytes.NewReader(wheelData), int64(len(wheelData)))
	if err != nil {
		return err
	}

	// Find the .dist-info directory
	for _, f := range reader.File {
		if strings.HasSuffix(f.Name, ".dist-info/METADATA") {
			distInfoDir := filepath.Dir(f.Name)
			installerPath := filepath.Join(sitePackagesPath, distInfoDir, "INSTALLER")
			return fsys.WriteFile(installerPath, []byte("apko\n"), 0644)
		}
	}

	return nil
}

// verifyChecksum verifies the SHA256 checksum of data against the expected value.
func verifyChecksum(data []byte, expected string) error {
	if expected == "" {
		return nil
	}

	prefix := "sha256:"
	if !strings.HasPrefix(expected, prefix) {
		return fmt.Errorf("unsupported checksum format: %s", expected)
	}
	expectedHex := expected[len(prefix):]

	h := sha256.Sum256(data)
	actualHex := hex.EncodeToString(h[:])

	if actualHex != expectedHex {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedHex, actualHex)
	}

	return nil
}
