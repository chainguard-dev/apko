// Copyright 2025 Chainguard, Inc.
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
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"testing"

	"chainguard.dev/apko/pkg/apk/apk"
	apkfs "chainguard.dev/apko/pkg/apk/fs"
)

func size(pkgs ...*apk.Package) uint64 {
	var total uint64
	for _, pkg := range pkgs {
		total += pkg.InstalledSize
	}
	return total
}

func TestGroupByOriginAndSize(t *testing.T) {
	crane := &apk.Package{Name: "crane", Origin: "crane", InstalledSize: 100}

	glibc := &apk.Package{Name: "glibc", Origin: "glibc", InstalledSize: 6113087}
	posix := &apk.Package{Name: "glibc-locale-posix", Origin: "glibc", InstalledSize: 417444}

	libcrypt1 := &apk.Package{Name: "libcrypt1", Origin: "glibc", Version: "2.38-r14", InstalledSize: 23508}
	libxcrypt := &apk.Package{Name: "libxcrypt", Origin: "libxcrypt", InstalledSize: 235761, Replaces: []string{"libcrypt1<2.38-r15"}}

	newcrypt1 := &apk.Package{Name: "libcrypt1", Origin: "glibc", Version: "2.38-r16", InstalledSize: 23508}

	repxcrypt := &apk.Package{Name: "libxcrypt", Origin: "libxcrypt", InstalledSize: 235761, Replaces: []string{"libcrypt1"}}
	for _, tc := range []struct {
		pkgs   []*apk.Package
		budget int
		want   []*group
		err    error
	}{{
		pkgs:   []*apk.Package{crane},
		budget: 1,
		want:   []*group{{pkgs: []*apk.Package{crane}, size: size(crane), tiebreaker: "crane"}},
	}, {
		// glibc and glibc-locale-posix should be grouped by origin
		pkgs:   []*apk.Package{crane, glibc, posix},
		budget: 2,
		want: []*group{
			{pkgs: []*apk.Package{glibc, posix}, size: size(glibc, posix), tiebreaker: "glibc-locale-posix"},
			{pkgs: []*apk.Package{crane}, size: size(crane), tiebreaker: "crane"},
		},
	}, {
		// reasonable default if budget is unspecified
		pkgs: []*apk.Package{crane, glibc, posix},
		want: []*group{
			{pkgs: []*apk.Package{crane, glibc, posix}, size: size(crane, glibc, posix), tiebreaker: "glibc-locale-posix"},
		},
	}, {
		// libxcrypt replace libcrypt1, so it should be merged into the glibc origin
		pkgs:   []*apk.Package{crane, glibc, posix, libcrypt1, libxcrypt},
		budget: 5,
		want: []*group{
			{pkgs: []*apk.Package{glibc, posix, libcrypt1, libxcrypt}, size: size(glibc, libcrypt1, libxcrypt, posix), tiebreaker: "libxcrypt"},
			{pkgs: []*apk.Package{crane}, size: size(crane), tiebreaker: "crane"},
		},
	}, {
		// libxcrypt replaces does not match the version constraint for "newcrypt1", so it doesn't get merged.
		pkgs:   []*apk.Package{crane, glibc, posix, newcrypt1, libxcrypt},
		budget: 5,
		want: []*group{
			{pkgs: []*apk.Package{glibc, posix, newcrypt1}, size: size(glibc, newcrypt1, posix), tiebreaker: "libcrypt1"},
			{pkgs: []*apk.Package{libxcrypt}, size: size(libxcrypt), tiebreaker: "libxcrypt"},
			{pkgs: []*apk.Package{crane}, size: size(crane), tiebreaker: "crane"},
		},
	}, {
		// "repxcrypt" replaces has no version, so it _does_ merge with "newcrypt1".
		pkgs:   []*apk.Package{crane, glibc, posix, newcrypt1, repxcrypt},
		budget: 5,
		want: []*group{
			{pkgs: []*apk.Package{glibc, posix, newcrypt1, repxcrypt}, size: size(glibc, newcrypt1, posix, repxcrypt), tiebreaker: "libxcrypt"},
			{pkgs: []*apk.Package{crane}, size: size(crane), tiebreaker: "crane"},
		},
	}, {
		// should be 3 groups but budget constricts that to 2
		pkgs:   []*apk.Package{crane, glibc, posix, newcrypt1, libxcrypt},
		budget: 2,
		want: []*group{
			{pkgs: []*apk.Package{glibc, posix, newcrypt1}, size: size(glibc, newcrypt1, posix), tiebreaker: "libcrypt1"},
			{pkgs: []*apk.Package{crane, libxcrypt}, size: size(crane, libxcrypt), tiebreaker: "libxcrypt"},
		},
	}} {
		got, err := groupByOriginAndSize(tc.pkgs, tc.budget)
		if err != nil && tc.err != nil {
			continue
		}

		if err != nil && tc.err == nil {
			t.Errorf("groupByOriginAndSize(%v, %d) unexpected error: %v", tc.pkgs, tc.budget, err)
		} else if err == nil && tc.err != nil {
			t.Errorf("groupByOriginAndSize(%v, %d) expected error: %v", tc.pkgs, tc.budget, tc.err)
		}

		if err := compareGroups(got, tc.want); err != nil {
			t.Errorf("groupByOriginAndSize(%v, %d) mismatch: %v", tc.pkgs, tc.budget, err)

			for i, g := range got {
				t.Logf("got[%d]: %v", i, g.pkgs)
			}
			for i, g := range tc.want {
				t.Logf("want[%d]: %v", i, g.pkgs)
			}
		}
	}
}

func compareGroups(a, b []*group) error {
	if len(a) != len(b) {
		return fmt.Errorf("len(a) = %d; len(b) = %d", len(a), len(b))
	}
	for i := range a {
		aa, bb := a[i], b[i]
		if len(aa.pkgs) != len(bb.pkgs) {
			return fmt.Errorf("len(a[%d].pkgs) = %d; len(b[%d].pkgs) = %d", i, len(aa.pkgs), i, len(bb.pkgs))
		}

		for j := range aa.pkgs {
			if aa.pkgs[j].Name != bb.pkgs[j].Name {
				return fmt.Errorf("a[%d].pkgs[%d] = %s; b[%d].pkgs[%d] = %s", i, j, aa.pkgs[j].Name, i, j, bb.pkgs[j].Name)
			}
		}

		if aa.size != bb.size {
			return fmt.Errorf("a[%d].size = %d; b[%d].size = %d", i, aa.size, i, bb.size)
		}
		if aa.tiebreaker != bb.tiebreaker {
			return fmt.Errorf("a[%d].tiebreaker = %s; b[%d].tiebreaker = %s", i, aa.tiebreaker, i, bb.tiebreaker)
		}
	}

	return nil
}

func TestAlignStacks(t *testing.T) {
	usr := []*file{{
		path: "usr",
	}, {
		path: "usr/lib",
	}}
	etc := []*file{{
		path: "etc",
	}, {
		path: "etc/apk",
	}, {
		path: "etc/apk/key",
	}}
	for i, tc := range []struct {
		stack  []*file
		before []*file
		diff   []*file
		after  []*file
	}{{
		stack:  usr,
		before: usr,
		after:  usr,
	}, {
		stack: usr,
		after: usr,
		diff:  usr,
	}, {
		stack:  usr,
		before: etc,
		after:  usr,
		diff:   usr,
	}, {
		stack:  etc,
		before: usr,
		after:  etc,
		diff:   etc,
	}, {
		stack:  etc[:2],
		before: etc,
		after:  etc[:2],
	}, {
		stack:  etc,
		before: etc[:2],
		after:  etc,
		diff:   etc[2:],
	}} {
		t.Run(fmt.Sprintf("case_%d", i), func(t *testing.T) {
			// clone to avoid mutating the usr and etc slices directly
			w := &layerWriter{stack: slices.Clone(tc.before)}

			if err := compareStacks(w.alignStacks(tc.stack), tc.diff); err != nil {
				t.Errorf("alignStacks() mismatch: %v", err)
			}
			if err := compareStacks(w.stack, tc.after); err != nil {
				t.Errorf("w.stack mismatch: %v", err)
			}
		})
	}
}

// NB: this only cares about path
func compareStacks(a, b []*file) error {
	if len(a) != len(b) {
		return fmt.Errorf("len(a) = %d; len(b) = %d", len(a), len(b))
	}

	for i := range len(a) {
		if a[i].path != b[i].path {
			return fmt.Errorf("a[%d] = %s; b[%d] = %s", i, a[i].path, i, b[i].path)
		}
	}

	return nil
}

func TestSplitLayersDirectoryCreation(t *testing.T) {
	// Create a minimal filesystem with an installed DB file
	fsys := apkfs.NewMemFS()

	// Create the parent directories first
	if err := fsys.MkdirAll("usr/lib/apk/db", 0755); err != nil {
		t.Fatalf("failed to create parent directories: %v", err)
	}

	// Create the installed DB file with some content
	idbContent := []byte("test db content")
	if err := fsys.WriteFile("usr/lib/apk/db/installed", idbContent, 0644); err != nil {
		t.Fatalf("failed to create installed DB file: %v", err)
	}

	// Create test packages for multiple layers
	pkg1 := &apk.Package{
		Name:          "pkg1",
		Origin:        "pkg1",
		Version:       "1.0.0",
		InstalledSize: 1000,
	}
	pkg2 := &apk.Package{
		Name:          "pkg2",
		Origin:        "pkg2",
		Version:       "1.0.0",
		InstalledSize: 2000,
	}

	// Create package groups (this will result in multiple layers)
	groups := []*group{
		{pkgs: []*apk.Package{pkg1}, size: 1000, tiebreaker: "pkg1"},
		{pkgs: []*apk.Package{pkg2}, size: 2000, tiebreaker: "pkg2"},
	}

	// Create package diffs (minimal content for each package)
	pkgToDiff := map[*apk.Package][]byte{
		pkg1: []byte("pkg1 info\n"),
		pkg2: []byte("pkg2 info\n"),
	}

	// Create temp directory for layer files
	tmpDir, err := os.MkdirTemp("", "layer-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Call splitLayers to create the layers
	ctx := context.Background()
	layers, err := splitLayers(ctx, fsys, groups, pkgToDiff, tmpDir)
	if err != nil {
		t.Fatalf("splitLayers failed: %v", err)
	}

	// We expect 3 layers: one for each package group + top layer
	if len(layers) != 3 {
		t.Fatalf("expected 3 layers, got %d", len(layers))
	}

	// Check each of the first 2 layers (package layers) for directory and file
	for i := range 2 {
		layer := layers[i]

		// Get layer content as tar reader
		rc, err := layer.Uncompressed()
		if err != nil {
			t.Fatalf("failed to get layer %d content: %v", i, err)
		}

		tr := tar.NewReader(rc)

		var foundDir, foundFile bool
		var entries []string

		// Read through the tar entries
		for {
			header, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("failed to read tar entry in layer %d: %v", i, err)
			}

			entries = append(entries, header.Name)

			// Check for the parent directory
			if header.Name == "usr/lib/apk/db" && header.Typeflag == tar.TypeDir {
				foundDir = true
			}

			// Check for the installed DB file
			if header.Name == "usr/lib/apk/db/installed" && header.Typeflag == tar.TypeReg {
				foundFile = true

				// Verify the file has content
				content, err := io.ReadAll(tr)
				if err != nil {
					t.Fatalf("failed to read installed DB content in layer %d: %v", i, err)
				}
				if len(content) == 0 {
					t.Errorf("installed DB file in layer %d is empty", i)
				}
			}
		}

		rc.Close()

		// Verify both directory and file were found
		if !foundDir {
			t.Errorf("layer %d missing parent directory 'usr/lib/apk/db' - this indicates the directory creation fix is not working", i)
			t.Logf("layer %d entries: %v", i, entries)
		}
		if !foundFile {
			t.Errorf("layer %d missing installed DB file 'usr/lib/apk/db/installed'", i)
			t.Logf("layer %d entries: %v", i, entries)
		}

		// The critical test: in a valid tar, directories must come before files
		// If the directory creation code is missing, the tar will be malformed
		var dirIndex, fileIndex = -1, -1
		for j, entry := range entries {
			if entry == "usr/lib/apk/db" {
				dirIndex = j
			}
			if entry == "usr/lib/apk/db/installed" {
				fileIndex = j
			}
		}

		if foundDir && foundFile && dirIndex > fileIndex {
			t.Errorf("layer %d has directory 'usr/lib/apk/db' (index %d) appearing after file 'usr/lib/apk/db/installed' (index %d) - this creates malformed tar", i, dirIndex, fileIndex)
		}
	}
}
