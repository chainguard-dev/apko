// Copyright 2025 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package paths

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestAdvertiseCachedFile(t *testing.T) {
	tmpDir := t.TempDir()
	src1 := tmpDir + "/src1.tmp"
	src2 := tmpDir + "/src2.tmp"
	src3 := tmpDir + "/src3.tmp"
	content := "content"

	for _, src := range []string{src1, src2, src3} {
		if err := os.WriteFile(src, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	dst := tmpDir + "/target"
	t.Run("dst does not exists", func(t *testing.T) {
		if err := AdvertiseCachedFile(src1, dst); err != nil {
			t.Fatal(err)
		}
		dstContent, err := os.ReadFile(dst)
		if err != nil {
			t.Fatal(err)
		}
		if string(dstContent) != content {
			t.Fatalf("content mismatch: %s != %s", string(dstContent), content)
		}
	})

	t.Run("dst exists", func(t *testing.T) {
		if err := AdvertiseCachedFile(src2, dst); err != nil {
			t.Fatal(err)
		}
		// check the symlink
		rel1, err := filepath.Rel(filepath.Dir(dst), src1)
		if err != nil {
			t.Fatal(err)
		}
		if l, err := os.Readlink(dst); err != nil {
			t.Fatal(err)
		} else if l != rel1 {
			t.Fatalf("symlink should stay in tact: %s != %s", l, src2)
		}

		// check that src2 is removed
		if _, err := os.Stat(src2); !os.IsNotExist(err) {
			t.Fatalf("src2 should be removed: %v", err)
		}
	})

	t.Run("dst exists, but is broken", func(t *testing.T) {
		// check the symlink
		rel1, err := filepath.Rel(filepath.Dir(dst), src1)
		if err != nil {
			t.Fatal(err)
		}
		if l, err := os.Readlink(dst); err != nil {
			t.Fatal(err)
		} else if l != rel1 {
			t.Fatalf("unexpected symlink: %s != %s", l, src2)
		}

		// remove the target to break the symlink
		if err := os.Remove(src1); err != nil {
			t.Fatal(err)
		}

		// now advertise src3 to dst
		if err := AdvertiseCachedFile(src3, dst); err != nil {
			t.Fatal(err)
		}
		// check the symlink
		rel2, err := filepath.Rel(filepath.Dir(dst), src3)
		if err != nil {
			t.Fatal(err)
		}
		if l, err := os.Readlink(dst); err != nil {
			t.Fatal(err)
		} else if l != rel2 {
			t.Fatalf("symlink should be updated: %s != %s", l, src2)
		}
	})
}

// TestReplaceCachedFile covers the counterpart to AdvertiseCachedFile, used when
// the caller holds content it has just verified. The difference that matters is
// who wins a collision: Advertise defers to whatever is already at the
// destination, which in a cache an attacker can write means adopting the planted
// entry and discarding the verified copy.
func TestReplaceCachedFile(t *testing.T) {
	for _, tc := range []struct {
		name string
		// plant puts something at dst before the call.
		plant func(t *testing.T, dst string)
	}{
		{name: "destination is absent"},
		{
			name: "destination is a stale regular file",
			plant: func(t *testing.T, dst string) {
				if err := os.WriteFile(dst, []byte("planted"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "destination is a symlink to somewhere else",
			plant: func(t *testing.T, dst string) {
				other := filepath.Join(t.TempDir(), "planted")
				if err := os.WriteFile(other, []byte("planted"), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(other, dst); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "destination is a dangling symlink",
			plant: func(t *testing.T, dst string) {
				if err := os.Symlink(filepath.Join(t.TempDir(), "gone"), dst); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			// rename(2) refuses to replace a directory. Without explicit handling
			// this wedges the entry permanently: the read path rejects it, the
			// refetch cannot install over it, and every later run repeats that.
			name: "destination is a directory",
			plant: func(t *testing.T, dst string) {
				if err := os.Mkdir(dst, 0o755); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "destination is a non-empty directory",
			plant: func(t *testing.T, dst string) {
				if err := os.Mkdir(dst, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dst, "junk"), []byte("junk"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			src := filepath.Join(dir, "src")
			if err := os.WriteFile(src, []byte("verified"), 0o644); err != nil {
				t.Fatal(err)
			}
			dst := filepath.Join(dir, "dst")
			if tc.plant != nil {
				tc.plant(t, dst)
			}

			if err := ReplaceCachedFile(src, dst); err != nil {
				t.Fatalf("ReplaceCachedFile: %v", err)
			}

			got, err := os.ReadFile(dst)
			if err != nil {
				t.Fatalf("reading %s: %v", dst, err)
			}
			if string(got) != "verified" {
				t.Errorf("dst holds %q; the planted entry won over the verified content", got)
			}

			// Relative, so a relocated cache directory keeps working.
			target, err := os.Readlink(dst)
			if err != nil {
				t.Fatalf("dst is not a symlink: %v", err)
			}
			if filepath.IsAbs(target) {
				t.Errorf("dst points at the absolute path %q; it should be relative", target)
			}

			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range entries {
				if strings.Contains(e.Name(), ".link-") {
					t.Errorf("scratch file left behind: %s", e.Name())
				}
			}
		})
	}
}

// TestReplaceCachedFileDisposesOfTheLoser covers the other half of winning a
// collision. AdvertiseCachedFile removed the loser's src; ReplaceCachedFile wins
// instead, so the loser is whatever dst pointed at, and a rename replaces only
// the symlink and not its target. Left alone that strands a full set of files on
// every lost fetch race and every poison repair, which nothing later revisits.
//
// The removal is bounded to dst's directory, and that bound is the security
// property: without it, a symlink planted at dst turns the next legitimate
// replacement into an arbitrary-file-deletion primitive.
func TestReplaceCachedFileDisposesOfTheLoser(t *testing.T) {
	for _, tc := range []struct {
		name string
		// plant sets dst up and returns the path that must survive or vanish.
		plant func(t *testing.T, dir, dst string) (victim string)
		// wantGone is whether the planted victim should be removed.
		wantGone bool
	}{
		{
			name: "the previously advertised file is removed",
			plant: func(t *testing.T, dir, dst string) string {
				sub := filepath.Join(dir, "expand-apk123")
				if err := os.Mkdir(sub, 0o755); err != nil {
					t.Fatal(err)
				}
				old := filepath.Join(sub, "stream-1.tar")
				if err := os.WriteFile(old, []byte("superseded"), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(old, dst); err != nil {
					t.Fatal(err)
				}
				return old
			},
			wantGone: true,
		},
		{
			// The whole reason the removal is scoped. An attacker who can write the
			// cache plants dst pointing anywhere; cleanup must not follow it out.
			name: "a planted symlink out of the directory is not followed",
			plant: func(t *testing.T, _, dst string) string {
				outside := filepath.Join(t.TempDir(), "precious")
				if err := os.WriteFile(outside, []byte("not ours to delete"), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, dst); err != nil {
					t.Fatal(err)
				}
				return outside
			},
			wantGone: false,
		},
		{
			name: "a dangling symlink leaves nothing to remove",
			plant: func(t *testing.T, dir, dst string) string {
				gone := filepath.Join(dir, "already-gone")
				if err := os.Symlink(gone, dst); err != nil {
					t.Fatal(err)
				}
				return gone
			},
			wantGone: true, // never existed; asserts only that this does not error
		},
		{
			// A regular file at dst is unlinked by the rename itself, so there is
			// no second thing to remove and no path to get wrong.
			name: "a regular file at the destination needs no cleanup",
			plant: func(t *testing.T, _, dst string) string {
				if err := os.WriteFile(dst, []byte("planted"), 0o644); err != nil {
					t.Fatal(err)
				}
				return dst
			},
			wantGone: false, // dst exists afterwards, as the new symlink
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			src := filepath.Join(dir, "src")
			if err := os.WriteFile(src, []byte("verified"), 0o644); err != nil {
				t.Fatal(err)
			}
			dst := filepath.Join(dir, "dst")
			victim := tc.plant(t, dir, dst)

			if err := ReplaceCachedFile(src, dst); err != nil {
				t.Fatalf("ReplaceCachedFile: %v", err)
			}

			// Whatever else happens, the verified content must be what dst serves.
			got, err := os.ReadFile(dst)
			if err != nil {
				t.Fatalf("reading %s: %v", dst, err)
			}
			if string(got) != "verified" {
				t.Errorf("dst holds %q, want the verified content", got)
			}

			_, statErr := os.Lstat(victim)
			if gone := os.IsNotExist(statErr); gone != tc.wantGone {
				t.Errorf("%s: exists=%v, want exists=%v", victim, !gone, !tc.wantGone)
			}
		})
	}
}

// TestReplaceCachedFileKeepsSrcWhenReadvertised guards the degenerate case:
// pointing dst at the file it already points at must not delete that file, which
// a naive "remove the old target" would do.
func TestReplaceCachedFileKeepsSrcWhenReadvertised(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("verified"), 0o644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "dst")

	for range 3 {
		if err := ReplaceCachedFile(src, dst); err != nil {
			t.Fatalf("ReplaceCachedFile: %v", err)
		}
		got, err := os.ReadFile(dst)
		if err != nil {
			t.Fatalf("reading %s after re-advertising: %v", dst, err)
		}
		if string(got) != "verified" {
			t.Fatalf("dst holds %q; re-advertising deleted the file it pointed at", got)
		}
	}
}

// TestReplaceCachedFileConcurrent enforces the doc comment's promise that a
// reader never observes dst missing or half-written. An implementation that
// unlinks before symlinking would make a warm cache look like a miss to anyone
// reading at the wrong moment.
func TestReplaceCachedFileConcurrent(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "dst")

	// A fresh file per advertisement, which is what the real caller does: each
	// process advertises files out of its own temp dir, once. Reusing a fixed set
	// would violate ReplaceCachedFile's advertise-once contract, since a src that
	// loses a collision is deleted.
	const writers = 8
	newSrc := func(t *testing.T, w, i int) string {
		t.Helper()
		src := filepath.Join(dir, fmt.Sprintf("src-%d-%d", w, i))
		if err := os.WriteFile(src, []byte("verified"), 0o644); err != nil {
			t.Fatal(err)
		}
		return src
	}
	if err := ReplaceCachedFile(newSrc(t, -1, 0), dst); err != nil {
		t.Fatal(err)
	}

	var (
		writeGroup sync.WaitGroup
		readGroup  sync.WaitGroup
		bad        atomic.Int64
		errs       = make(chan error, writers)
		stop       = make(chan struct{})
	)

	for range 4 {
		readGroup.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				if b, err := os.ReadFile(dst); err != nil || string(b) != "verified" {
					bad.Add(1)
				}
			}
		})
	}

	for w := range writers {
		writeGroup.Go(func() {
			for i := range 200 {
				if err := ReplaceCachedFile(newSrc(t, w, i), dst); err != nil {
					errs <- err
					return
				}
			}
		})
	}

	writeGroup.Wait()
	close(stop)
	readGroup.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent ReplaceCachedFile failed: %v", err)
	}
	if n := bad.Load(); n != 0 {
		t.Errorf("a concurrent reader saw %d missing or partial reads of %s; the replacement is not atomic", n, dst)
	}
}
