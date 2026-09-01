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

package ldsocache

import (
	"debug/elf"
	"testing"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/elfmeta"
)

// TestStampedMetadataSkipsParsing proves the pre-computed path: files whose
// content is deliberately not ELF at all still produce cache entries when
// they carry stamped metadata — the scan never opened them — and a stamp
// that says "not a dynamic object" excludes a file without a parse.
func TestStampedMetadataSkipsParsing(t *testing.T) {
	// Sibling tests swap the package-global parser for a mock; this test is
	// about the real one being bypassed, so pin it.
	orig := getElfInfo
	getElfInfo = doGetElfInfo
	t.Cleanup(func() { getElfInfo = orig })

	fsys := apkfs.NewMemFS()
	if err := fsys.MkdirAll("usr/lib", 0o755); err != nil {
		t.Fatal(err)
	}

	// Not an ELF; only the stamp makes it legible.
	if err := fsys.WriteFile("usr/lib/libstamped.so.1", []byte("not an ELF"), 0o644); err != nil {
		t.Fatal(err)
	}
	stamp := elfmeta.Info{Dyn: true, Machine: elf.EM_AARCH64, Sonames: []string{"libstamped.so.1"}}
	if err := fsys.SetXattr("usr/lib/libstamped.so.1", elfmeta.Xattr, stamp.Encode()); err != nil {
		t.Fatal(err)
	}

	// Stamped "checked, not a dynamic object": excluded, also without a parse.
	if err := fsys.WriteFile("usr/lib/libnotdyn.so.1", []byte("also not an ELF"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fsys.SetXattr("usr/lib/libnotdyn.so.1", elfmeta.Xattr, elfmeta.Info{}.Encode()); err != nil {
		t.Fatal(err)
	}

	// A symlink to the stamped file: facts resolve through the link.
	if err := fsys.Symlink("libstamped.so.1", "usr/lib/libstamped.so"); err != nil {
		t.Fatal(err)
	}

	// Unstamped garbage: parses, fails, skipped — the fallback path.
	if err := fsys.WriteFile("usr/lib/libplain.so.1", []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}

	entries, err := LDSOCacheEntriesForDirs(fsys, []string{"/usr/lib"})
	if err != nil {
		t.Fatalf("LDSOCacheEntriesForDirs: %v", err)
	}
	names := map[string]bool{}
	for _, e := range entries {
		names[e.Name] = true
	}
	if !names["/usr/lib/libstamped.so.1"] {
		t.Errorf("stamped library missing from cache entries: %v", entries)
	}
	for _, absent := range []string{"/usr/lib/libnotdyn.so.1", "/usr/lib/libplain.so.1"} {
		if names[absent] {
			t.Errorf("%s: got = a cache entry, wanted = none", absent)
		}
	}
}
