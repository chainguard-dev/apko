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

package tarfs

import (
	"archive/tar"
	"context"
	"path/filepath"
	"testing"

	"chainguard.dev/apko/pkg/build"
)

func TestTarFS(t *testing.T) {
	tfs := New()
	ctx := context.Background()

	opts := []build.Option{
		build.WithConfig(filepath.Join("testdata", "tzdata.yaml")),
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
	pkg := installed[0]
	want := "usr/share/zoneinfo/zone.tab"
	var file *tar.Header
	for _, hdr := range pkg.Files {
		if hdr.Name == want {
			file = hdr
			break
		}
	}
	if file == nil {
		t.Fatalf("did not find %q", want)
	}
	file.Typeflag = tar.TypeReg

	if _, err := tfs.WriteHeader(*file, tfs, &pkg.Package); err == nil {
		t.Errorf("wanted missing checksum err, got nil")
	}

	file.PAXRecords = map[string]string{
		"APK-TOOLS.checksum.SHA1": "Q1v+13wxZjoZUgI11oT2c7+ZUPjgw=",
	}
	if _, err := tfs.WriteHeader(*file, tfs, &pkg.Package); err != nil {
		t.Errorf("matching checksum should be skipped, got %v", err)
	}

	file.PAXRecords = map[string]string{
		"APK-TOOLS.checksum.SHA1": "Q1v+12wxZjoZUgI11oT2c7+ZUPjgw=",
	}
	pkg.Origin += "-different"
	if _, err := tfs.WriteHeader(*file, tfs, &pkg.Package); err == nil {
		t.Errorf("wanted conflicting checksum err, got nil")
	}

	pkg.Replaces = []string{pkg.Name}
	if _, err := tfs.WriteHeader(*file, tfs, &pkg.Package); err != nil {
		t.Errorf("pkg replaces file, got %v", err)
	}
}
