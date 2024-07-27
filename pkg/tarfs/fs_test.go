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

package tarfs_test

import (
	"archive/tar"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"path/filepath"
	"testing"

	"chainguard.dev/apko/pkg/apk/apk"

	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/tarfs"
)

func TestTarFS(t *testing.T) {
	tfs := tarfs.New()
	ctx := context.Background()

	opts := []build.Option{
		build.WithConfig(filepath.Join("testdata", "apko.yaml"), []string{}),
	}

	bc, err := build.New(ctx, tfs, opts...)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := bc.BuildLayer(ctx); err != nil {
		t.Fatal(err)
	}

	installed, err := bc.InstalledPackages()
	if err != nil {
		t.Fatal(err)
	}

	// Check that everything in installed was written.
	for _, pkg := range installed {
		for _, hdr := range pkg.Files {
			// It should exist at least.
			stat, err := tfs.Stat(hdr.Name)
			if err != nil {
				t.Errorf("stat file %q: %v", hdr.Name, err)
				continue
			}

			if stat.Size() == 0 {
				continue
			}

			if _, err := tfs.Open(hdr.Name); err != nil {
				t.Errorf("opening %q: %v", hdr.Name, err)
			}
		}
	}

	// Pull a file out of the apk that we know exists and hit a bunch of edge cases.
	pkg := installed[1]
	want := "etc/os-release"
	var file *tar.Header
	for _, hdr := range pkg.Files {
		if hdr.Name == want {
			file = &hdr
			break
		}
	}
	if file == nil {
		t.Fatalf("did not find %q", want)
		return
	}
	file.Typeflag = tar.TypeReg

	if _, err := tfs.WriteHeader(*file, tfs, &pkg.Package); err == nil {
		t.Errorf("wanted missing checksum err, got nil")
	}

	otherPkg := &apk.Package{Origin: "different", Name: "different"}

	// # https://github.com/jonjohnsonjr/tarp
	// $ cat internal/cli/testdata/packages/aarch64/replayout-1.0.0-r0.apk | gunzip | tarp | grep "etc/os-release" | jq .PAXRecords -c
	// {"APK-TOOLS.checksum.SHA1":"ca5e527bbb8a5cc9c4c2d2b4e29618d8ca3be5f8"}
	file.PAXRecords = map[string]string{
		"APK-TOOLS.checksum.SHA1": "ca5e527bbb8a5cc9c4c2d2b4e29618d8ca3be5f8",
	}
	if _, err := tfs.WriteHeader(*file, tfs, otherPkg); err != nil {
		t.Errorf("matching checksum should be skipped, got %v", err)
	}

	file.PAXRecords = map[string]string{
		"APK-TOOLS.checksum.SHA1": "0000000000000000000000000000000000000000",
	}
	if _, err := tfs.WriteHeader(*file, tfs, otherPkg); err == nil {
		t.Errorf("wanted conflicting checksum err, got nil")
	}

	otherPkg.Replaces = []string{pkg.Name}
	if _, err := tfs.WriteHeader(*file, tfs, otherPkg); err != nil {
		t.Errorf("pkg replaces file, got %v", err)
	}

	// Ensure that symlinks work with replaces.
	{
		original := tar.Header{
			Name:     "etc/os-release-symlink",
			Typeflag: tar.TypeSymlink,
			Linkname: "etc/os-release-symlink",
		}
		originalDigest := sha1.Sum([]byte(original.Linkname)) //nolint:gosec
		originalChecksum := hex.EncodeToString(originalDigest[:])
		original.PAXRecords = map[string]string{
			"APK-TOOLS.checksum.SHA1": originalChecksum,
		}

		if _, err := tfs.WriteHeader(original, tfs, &pkg.Package); err != nil {
			t.Fatalf("symlinking: %v", err)
		}

		link := tar.Header{
			Name:     "etc/os-release-symlink",
			Typeflag: tar.TypeSymlink,
			Linkname: "etc/somewhere-else",
		}
		linkDigest := sha1.Sum([]byte(link.Linkname)) //nolint:gosec
		linkChecksum := hex.EncodeToString(linkDigest[:])
		link.PAXRecords = map[string]string{
			"APK-TOOLS.checksum.SHA1": linkChecksum,
		}

		if _, err := tfs.WriteHeader(link, tfs, otherPkg); err != nil {
			t.Errorf("pkg replaces symlink, got %v", err)
		}
	}
}
