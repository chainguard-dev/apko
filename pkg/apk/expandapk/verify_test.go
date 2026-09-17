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

package expandapk

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/klauspost/compress/gzip"
	"golang.org/x/sys/unix"
)

// dataSection writes a data.tar.gz / data.tar pair into dir, mimicking the two
// files cachePackage leaves behind for a package's data section, and returns an
// APKExpanded pointing at them alongside the digest of each.
func dataSection(t *testing.T, dir string, payload []byte) (*APKExpanded, []byte, []byte) {
	t.Helper()

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(payload); err != nil {
		t.Fatalf("compressing payload: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("closing gzip writer: %v", err)
	}

	gzPath := filepath.Join(dir, "data.tar.gz")
	tarPath := filepath.Join(dir, "data.tar")
	if err := os.WriteFile(gzPath, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("writing %s: %v", gzPath, err)
	}
	if err := os.WriteFile(tarPath, payload, 0o644); err != nil {
		t.Fatalf("writing %s: %v", tarPath, err)
	}

	gzSum := sha256.Sum256(buf.Bytes())
	tarSum := sha256.Sum256(payload)
	return &APKExpanded{PackageFile: gzPath, TarFile: tarPath}, gzSum[:], tarSum[:]
}

func readAllFrom(t *testing.T, f *os.File) []byte {
	t.Helper()

	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("reading returned handle: %v", err)
	}
	return b
}

// TestVerifiedPackageData covers the cache-read integrity check: the compressed
// data section must hash to the datahash carried in the verified control
// section, and what is served must be inflated from those verified bytes into
// storage nothing else can reach.
func TestVerifiedPackageData(t *testing.T) {
	payload := []byte("this stands in for the package data tar")

	for _, tc := range []struct {
		name string
		// setup mutates the on-disk pair after it has been written, and returns
		// the digest to verify against (nil means "the correct one").
		setup func(t *testing.T, a *APKExpanded, gzSum, tarSum []byte) []byte
		// wantErr, when non-empty, is a substring of the expected rejection.
		wantErr string
	}{
		{
			name: "matching pair is served",
		},
		{
			name: "wrong datahash is rejected",
			setup: func(_ *testing.T, _ *APKExpanded, _, _ []byte) []byte {
				return make([]byte, sha256.Size)
			},
			wantErr: "data hash mismatch",
		},
		{
			name: "tampered .tar.gz is rejected even though the .tar is intact",
			setup: func(t *testing.T, a *APKExpanded, _, _ []byte) []byte {
				var buf bytes.Buffer
				zw := gzip.NewWriter(&buf)
				if _, err := zw.Write([]byte("attacker payload")); err != nil {
					t.Fatalf("compressing: %v", err)
				}
				if err := zw.Close(); err != nil {
					t.Fatalf("closing gzip writer: %v", err)
				}
				if err := os.WriteFile(a.PackageFile, buf.Bytes(), 0o644); err != nil {
					t.Fatalf("writing %s: %v", a.PackageFile, err)
				}
				return nil
			},
			wantErr: "data hash mismatch",
		},
		{
			// Caught by the digest rather than by gzip: the inflater stops at the
			// trailer and never looks at these bytes, so they are only covered
			// because the remainder of the section is drained through the hasher
			// after inflation. Drop that drain and the digest silently becomes a
			// digest of the prefix, and anything can be appended to a valid entry.
			name: "garbage appended to a valid .tar.gz is rejected",
			setup: func(t *testing.T, a *APKExpanded, _, _ []byte) []byte {
				f, err := os.OpenFile(a.PackageFile, os.O_APPEND|os.O_WRONLY, 0o644)
				if err != nil {
					t.Fatalf("opening %s: %v", a.PackageFile, err)
				}
				defer f.Close()
				if _, err := f.Write([]byte("trailing bytes")); err != nil {
					t.Fatalf("appending: %v", err)
				}
				return nil
			},
			wantErr: "data hash mismatch",
		},
		{
			// The uncompressed tar in the cache is not consulted at all, so
			// whatever it holds is irrelevant rather than merely detected.
			name: "tampered .tar is ignored",
			setup: func(t *testing.T, a *APKExpanded, _, _ []byte) []byte {
				if err := os.WriteFile(a.TarFile, []byte("attacker payload"), 0o644); err != nil {
					t.Fatalf("writing %s: %v", a.TarFile, err)
				}
				return nil
			},
		},
		{
			name: "missing .tar is irrelevant",
			setup: func(t *testing.T, a *APKExpanded, _, _ []byte) []byte {
				if err := os.Remove(a.TarFile); err != nil {
					t.Fatalf("removing %s: %v", a.TarFile, err)
				}
				return nil
			},
		},
		{
			name: "a .tar symlinked to an attacker file is ignored",
			setup: func(t *testing.T, a *APKExpanded, _, _ []byte) []byte {
				planted := filepath.Join(t.TempDir(), "planted")
				if err := os.WriteFile(planted, []byte("attacker payload"), 0o644); err != nil {
					t.Fatalf("writing %s: %v", planted, err)
				}
				if err := os.Remove(a.TarFile); err != nil {
					t.Fatalf("removing %s: %v", a.TarFile, err)
				}
				if err := os.Symlink(planted, a.TarFile); err != nil {
					t.Fatalf("symlinking %s: %v", a.TarFile, err)
				}
				return nil
			},
		},
		{
			name: "a directory at .tar.gz is refused",
			setup: func(t *testing.T, a *APKExpanded, _, _ []byte) []byte {
				if err := os.Remove(a.PackageFile); err != nil {
					t.Fatalf("removing %s: %v", a.PackageFile, err)
				}
				if err := os.Mkdir(a.PackageFile, 0o755); err != nil {
					t.Fatalf("mkdir %s: %v", a.PackageFile, err)
				}
				return nil
			},
			wantErr: "not a regular file",
		},
		{
			// os.Stat is happy with a FIFO and a blocking open on one never
			// returns, so the type has to be established from the descriptor.
			name: "a named pipe at .tar.gz is refused rather than opened",
			setup: func(t *testing.T, a *APKExpanded, _, _ []byte) []byte {
				if err := os.Remove(a.PackageFile); err != nil {
					t.Fatalf("removing %s: %v", a.PackageFile, err)
				}
				if err := syscall.Mkfifo(a.PackageFile, 0o644); err != nil {
					t.Skipf("cannot create a fifo here: %v", err)
				}
				return nil
			},
			wantErr: "not a regular file",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			a, gzSum, tarSum := dataSection(t, dir, payload)

			want := gzSum
			if tc.setup != nil {
				if override := tc.setup(t, a, gzSum, tarSum); override != nil {
					want = override
				}
			}

			tarBefore, tarStatErr := os.Lstat(a.TarFile)

			// A regression that reintroduces a blocking open would otherwise hang
			// the whole package rather than failing this one case.
			type result struct {
				f   *os.File
				err error
			}
			ch := make(chan result, 1)
			go func() {
				f, err := a.VerifiedPackageData(want)
				ch <- result{f, err}
			}()

			var got result
			select {
			case got = <-ch:
			case <-time.After(30 * time.Second):
				t.Fatalf("VerifiedPackageData blocked; it must never issue a blocking open on a cache path")
			}

			if tc.wantErr != "" {
				if got.err == nil {
					served := readAllFrom(t, got.f)
					got.f.Close()
					t.Fatalf("want error containing %q, got nil (served %d bytes: %q)", tc.wantErr, len(served), served)
				}
				if !strings.Contains(got.err.Error(), tc.wantErr) {
					t.Fatalf("want error containing %q, got %v", tc.wantErr, got.err)
				}
				return
			}

			if got.err != nil {
				t.Fatalf("want the legitimate pair to be served, got error: %v", got.err)
			}
			defer got.f.Close()

			if b := readAllFrom(t, got.f); !bytes.Equal(payload, b) {
				t.Fatalf("served the wrong bytes: want %q, got %q", payload, b)
			}

			// The descriptor must have no name left on disk. If it has one, an
			// attacker has somewhere to write and the verification is only a
			// statement about the past.
			if _, err := os.Lstat(got.f.Name()); !os.IsNotExist(err) {
				t.Errorf("served descriptor is still reachable at %q (stat err = %v); it must be unlinked",
					got.f.Name(), err)
			}

			// Nothing in the cache should have been written, including the
			// uncompressed tar, which is neither read nor refreshed.
			tarAfter, err := os.Lstat(a.TarFile)
			switch {
			case tarStatErr != nil && err == nil:
				t.Errorf("%s did not exist before the call but does now", a.TarFile)
			case tarStatErr == nil && err != nil:
				t.Errorf("%s existed before the call but not after: %v", a.TarFile, err)
			case tarStatErr == nil && err == nil && !os.SameFile(tarBefore, tarAfter):
				t.Errorf("%s was replaced (was mode %v, now mode %v); the cached tar is not read, so it must not be rewritten either",
					a.TarFile, tarBefore.Mode(), tarAfter.Mode())
			}
		})
	}
}

// TestVerifiedPackageDataSurvivesInPlaceRewrite is the reason the served copy is
// private. Measuring a file and then reading it again later are two reads of a
// mutable object: an attacker who overwrites the verified bytes in place,
// without unlinking or renaming, defeats any check made ahead of time. Serving
// an unlinked copy removes the name they would need.
func TestVerifiedPackageDataSurvivesInPlaceRewrite(t *testing.T) {
	payload := []byte("LEGITIMATE package data tar contents, padded out a little")

	dir := t.TempDir()
	a, gzSum, _ := dataSection(t, dir, payload)

	f, err := a.VerifiedPackageData(gzSum)
	if err != nil {
		t.Fatalf("VerifiedPackageData: %v", err)
	}
	defer f.Close()

	// Same inode, same length, no rename and no unlink: the shapes IsValid and a
	// path-based recheck both fail to notice.
	evil := []byte("PWNED!!!!! package data tar contents, padded out a little")
	if len(evil) != len(payload) {
		t.Fatalf("test bug: replacement must be the same length (%d vs %d)", len(evil), len(payload))
	}
	for _, path := range []string{a.TarFile, a.PackageFile} {
		w, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			t.Fatalf("opening %s for the in-place rewrite: %v", path, err)
		}
		if _, err := w.WriteAt(evil, 0); err != nil {
			t.Fatalf("rewriting %s: %v", path, err)
		}
		w.Close()
	}

	got := readAllFrom(t, f)
	if !bytes.Equal(payload, got) {
		t.Fatalf("an in-place rewrite of the cache changed what the verified descriptor serves:\n want %q\n got  %q", payload, got)
	}
}

// nlinkOf returns the link count of the inode behind f.
//
// The conversion is load-bearing for portability: st_nlink is uint64 on Linux
// but uint16 on darwin, so returning the field directly compiles on only one of
// the platforms apko releases for.
func nlinkOf(t *testing.T, f *os.File) uint64 {
	t.Helper()

	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		t.Fatalf("fstat: %v", err)
	}
	// nolint:unconvert // Redundant on Linux, where st_nlink is already uint64,
	// but required on darwin, where it is uint16. The linter only ever sees the
	// Linux definition.
	return uint64(st.Nlink)
}

// TestPrivateFile covers the unlinked-copy primitive directly.
func TestPrivateFile(t *testing.T) {
	t.Run("has no links at all", func(t *testing.T) {
		// The property the whole design rests on. A single remaining link is a
		// name somebody else can open and write through, which would put the
		// served bytes back under their control.
		dir := t.TempDir()
		f, err := privateFile(dir)
		if err != nil {
			t.Fatalf("privateFile: %v", err)
		}
		defer f.Close()

		if n := nlinkOf(t, f); n != 0 {
			t.Errorf("private copy has %d link(s); it must have none", n)
		}
	})

	t.Run("is unlinked but writable", func(t *testing.T) {
		dir := t.TempDir()
		f, err := privateFile(dir)
		if err != nil {
			t.Fatalf("privateFile: %v", err)
		}
		defer f.Close()

		if _, err := os.Lstat(f.Name()); !os.IsNotExist(err) {
			t.Errorf("%q is still reachable by name (stat err = %v)", f.Name(), err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Errorf("privateFile left %d entries behind in %s", len(entries), dir)
		}

		if _, err := f.Write([]byte("payload")); err != nil {
			t.Fatalf("writing to the private file: %v", err)
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		if got := readAllFrom(t, f); string(got) != "payload" {
			t.Errorf("private file round-trip: got %q", got)
		}
	})

	// The windowless O_TMPFILE path is asserted in verify_linux_test.go, since
	// it is a guarantee only that platform makes.

	t.Run("the named fallback never returns a descriptor that still has a link", func(t *testing.T) {
		// unlinkedTempFile has to publish a name, and anyone with write access to
		// the directory can hardlink it before the unlink lands. They then hold a
		// second reference and can write through it, changing what the verified
		// descriptor serves. protected_hardlinks does not prevent that when the
		// attacker shares our uid, which is the co-tenant case in this threat
		// model, so the link count has to be checked.
		//
		// Driven against unlinkedTempFile directly, because on Linux the
		// O_TMPFILE path would pre-empt the fallback and never exercise it.
		//
		// The race is probabilistic but the assertion is not: whether or not the
		// linker wins any given round, no descriptor handed back may have a
		// surviving link.
		dir := t.TempDir()

		stop := make(chan struct{})
		var linker sync.WaitGroup
		linker.Go(func() {
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				entries, err := os.ReadDir(dir)
				if err != nil {
					continue
				}
				for _, e := range entries {
					if !strings.HasPrefix(e.Name(), ".apko-data-") {
						continue
					}
					_ = os.Link(filepath.Join(dir, e.Name()),
						filepath.Join(dir, fmt.Sprintf("stolen-%d", i)))
				}
			}
		})

		var served, refused int
		for range 2000 {
			f, err := unlinkedTempFile(dir)
			if err != nil {
				refused++
				continue
			}
			served++
			if n := nlinkOf(t, f); n != 0 {
				f.Close()
				close(stop)
				linker.Wait()
				t.Fatalf("unlinkedTempFile returned a descriptor with %d surviving link(s); "+
					"another process can write through that name and change what is served", n)
			}
			f.Close()
		}
		close(stop)
		linker.Wait()

		t.Logf("served=%d refused=%d", served, refused)
		if served == 0 {
			t.Error("every attempt was refused, so this asserted nothing about the served path")
		}
	})

	t.Run("falls back when the preferred directory is not writable", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("running as root; directory modes do not restrict us")
		}
		// A read-only cache directory is a legitimate deployment, and a build over
		// one has to keep working.
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

		f, err := privateFile(dir)
		if err != nil {
			t.Fatalf("privateFile must fall back to the system temp dir, got: %v", err)
		}
		defer f.Close()
		if _, err := os.Lstat(f.Name()); !os.IsNotExist(err) {
			t.Errorf("fallback file %q is still reachable by name", f.Name())
		}
	})
}

// TestVerifiedPackageDataReadOnlyCache checks the deployment the private copy
// most easily breaks: a cache directory nobody can write to.
func TestVerifiedPackageDataReadOnlyCache(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; directory modes do not restrict us")
	}

	payload := []byte("this stands in for the package data tar")
	dir := t.TempDir()
	a, gzSum, _ := dataSection(t, dir, payload)

	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	f, err := a.VerifiedPackageData(gzSum)
	if err != nil {
		t.Fatalf("a read-only cache with a valid entry must still be served, got: %v", err)
	}
	defer f.Close()
	if got := readAllFrom(t, f); !bytes.Equal(payload, got) {
		t.Fatalf("served the wrong bytes: want %q, got %q", payload, got)
	}
}

// TestMaxCompressedSize pins the relationship between the two limits. Using the
// decompressed bound directly on the compressed file rejects real packages,
// because gzip expands incompressible input.
func TestMaxCompressedSize(t *testing.T) {
	for _, tc := range []struct {
		name    string
		maxData int64
		want    int64
	}{
		{name: "unlimited stays unlimited", maxData: -1, want: 0},
		{name: "unset stays unset", maxData: 0, want: 0},
		{name: "a limit gains an allowance for gzip overhead", maxData: 1 << 20, want: 1<<20 + (1<<20)/1000 + 4096},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := maxCompressedSize(tc.maxData); got != tc.want {
				t.Errorf("maxCompressedSize(%d) = %d, want %d", tc.maxData, got, tc.want)
			}
		})
	}
}

// TestVerifiedPackageDataIncompressiblePayload is the regression that motivates
// maxCompressedSize: a data section at exactly the configured limit gzips to
// slightly more than it, and bounding the compressed file by the decompressed
// limit would make such a package permanently uninstallable.
func TestVerifiedPackageDataIncompressiblePayload(t *testing.T) {
	// Genuinely incompressible: chained SHA-256 output. A counter would not do,
	// since its 256-byte period compresses away and the compressed form would
	// land under the limit, quietly turning this into a test of nothing.
	payload := make([]byte, 0, 1<<20)
	block := sha256.Sum256([]byte("psec-1800"))
	for len(payload) < 1<<20 {
		payload = append(payload, block[:]...)
		block = sha256.Sum256(block[:])
	}
	payload = payload[:1<<20]

	dir := t.TempDir()
	a, gzSum, _ := dataSection(t, dir, payload)
	if err := a.ApplyOptions(WithMaxDataSize(int64(len(payload)))); err != nil {
		t.Fatal(err)
	}

	gzInfo, err := os.Stat(a.PackageFile)
	if err != nil {
		t.Fatal(err)
	}
	if gzInfo.Size() <= int64(len(payload)) {
		t.Fatalf("test bug: payload compressed to %d bytes, at or below the %d byte limit, so this case "+
			"would not exercise the compressed-vs-decompressed bound at all", gzInfo.Size(), len(payload))
	}

	f, err := a.VerifiedPackageData(gzSum)
	if err != nil {
		t.Fatalf("a data section at exactly MaxDataSize must be served, but its %d byte compressed form was rejected: %v",
			gzInfo.Size(), err)
	}
	defer f.Close()
	if got := readAllFrom(t, f); !bytes.Equal(payload, got) {
		t.Fatal("served the wrong bytes")
	}
}

// TestVerifiedPackageDataHonoursMaxDataSize proves the configured limit reaches
// the cache-read path, in both directions.
func TestVerifiedPackageDataHonoursMaxDataSize(t *testing.T) {
	payload := []byte("this stands in for the package data tar")

	for _, tc := range []struct {
		name    string
		opts    []Option
		wantErr string
	}{
		{name: "no configured limit serves the entry"},
		{name: "unlimited serves the entry", opts: []Option{WithMaxDataSize(-1)}},
		{name: "a generous limit serves the entry", opts: []Option{WithMaxDataSize(1 << 20)}},
		{
			name:    "a limit below the decompressed size rejects the entry",
			opts:    []Option{WithMaxDataSize(8)},
			wantErr: "size limit exceeded",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			a, gzSum, _ := dataSection(t, dir, payload)
			if err := a.ApplyOptions(tc.opts...); err != nil {
				t.Fatal(err)
			}

			f, err := a.VerifiedPackageData(gzSum)
			if tc.wantErr != "" {
				if err == nil {
					f.Close()
					t.Fatalf("want the configured limit to reject the entry, got nil")
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want an error containing %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("want the entry served with opts %v, got %v", tc.opts, err)
			}
			f.Close()
		})
	}
}

// TestApplyOptions covers the accessor the cache-read path depends on, since it
// is the only way limits reach an APKExpanded that ExpandApk did not build.
func TestApplyOptions(t *testing.T) {
	for _, tc := range []struct {
		name        string
		opts        []Option
		wantMaxData int64
		wantErr     string
	}{
		{name: "no options leaves the defaults", wantMaxData: DefaultMaxDataSize},
		{name: "a data limit is applied", opts: []Option{WithMaxDataSize(4096)}, wantMaxData: 4096},
		{name: "unlimited is applied", opts: []Option{WithMaxDataSize(-1)}, wantMaxData: -1},
		{
			name:        "a control limit leaves the data limit alone",
			opts:        []Option{WithMaxControlSize(4096)},
			wantMaxData: DefaultMaxDataSize,
		},
		{
			name:    "a failing option is surfaced",
			opts:    []Option{func(*Options) error { return errBadOption }},
			wantErr: "applying option",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &APKExpanded{}
			err := a.ApplyOptions(tc.opts...)

			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("want an error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want an error containing %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ApplyOptions(%v): %v", tc.opts, err)
			}
			if got := a.maxDataSize(); got != tc.wantMaxData {
				t.Errorf("maxDataSize() = %d, want %d", got, tc.wantMaxData)
			}
		})
	}
}

var errBadOption = errors.New("bad option")
