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
// reader never observes dst half-written or holding stale content. An
// implementation that unlinks before symlinking, or that publishes before the
// content is in place, would be caught here.
//
// It deliberately does *not* require every read to succeed. A reader
// intermittently fails to read dst -- ENOENT, or EISDIR on a path that is only
// ever a symlink -- a handful of times in tens of thousands of reads, which
// made this test flaky enough to redden main. The evidence so far points away
// from ReplaceCachedFile: the destination is a symlink on every observation and
// is never unlinked, the one branch that could briefly remove it never runs,
// and the same failure reproduces outside this repository with no apko or Go
// code involved. Whether that is genuine kernel behaviour or something still
// wrong in how these entries are published is being chased separately in
// PSEC-2866, so treat the tolerance below as provisional rather than settled.
//
// Tolerating failures without a bound would make the test worthless, because an
// implementation that unlinks before symlinking produces nothing but misses. So
// two assertions replace the one:
//
//   - A read that *completes* must never return anything but the published
//     content. Anything else is a torn or stale publish, which is the promise.
//   - Reads that do not complete must stay rare. The two cases are far apart: a
//     correct implementation gives zero incomplete reads out of ~34,000, while
//     unlink-then-symlink gives ~51,000 out of ~78,000.
//
// A rare incomplete read is in any case indistinguishable from a cache miss to
// every caller in this repo, and getPackageImpl already treats a miss as
// something the refetch repairs.
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
		bad        atomic.Int64 // reads that completed and returned the wrong bytes
		good       atomic.Int64 // reads that completed and returned the right bytes
		transient  atomic.Int64 // reads that did not complete; see the doc comment
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
				b, err := os.ReadFile(dst)
				if err != nil {
					// Not a finding: see the doc comment. Counted so the
					// assertion below can tell "the race never ran" apart
					// from "the race ran and every completed read was good".
					transient.Add(1)
					continue
				}
				if string(b) != "verified" {
					bad.Add(1)
					continue
				}
				good.Add(1)
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
		t.Errorf("a concurrent reader saw %d torn or stale reads of %s; the replacement is not atomic "+
			"(%d reads completed correctly, %d did not complete)", n, dst, good.Load(), transient.Load())
	}
	// Incomplete reads are tolerated but not unlimited, which is what keeps a
	// non-atomic publish detectable. The two cases are orders of magnitude
	// apart: a correct implementation produces zero incomplete reads in a
	// typical run of ~34,000, while unlinking before symlinking produces around
	// 50,000 out of ~80,000 -- roughly two thirds of every read. Anything above
	// a per-cent of completed reads is a publish that is not atomic, not the
	// resolution race described above.
	if n, ok := transient.Load(), good.Load(); n > max(ok/100, 32) {
		t.Errorf("%d of %d reads of %s did not complete; at that rate dst is being "+
			"published non-atomically rather than losing the occasional resolution race",
			n, n+ok, dst)
	}
	// Without this the test would still pass if every read failed to complete,
	// which would make the assertion above vacuous.
	if good.Load() == 0 {
		t.Errorf("no read of %s ever completed (%d did not complete); this asserted nothing",
			dst, transient.Load())
	}
}
