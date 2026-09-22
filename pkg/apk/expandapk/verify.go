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
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"syscall"

	"github.com/klauspost/compress/gzip"
	"golang.org/x/sys/unix"

	"chainguard.dev/apko/pkg/limitio"
)

// VerifiedPackageData returns an open, rewound descriptor for the uncompressed
// data tar, inflated from a compressed data section whose SHA-256 is want.
//
// want is the digest .PKGINFO records as datahash, which the apk format defines
// over the *compressed* data stream. It is therefore the same value the fetch
// path compares against APKExpanded.PackageHash, and hashing the decompressed
// bytes against it would never match.
//
// The returned descriptor refers to an unlinked, process-private file. That is
// the whole point of this function, and the reason it does not read TarFile:
// the uncompressed tar has no authenticated digest anywhere in the apk format,
// so the only thing that can be said about a copy of it is that it was inflated
// from bytes that did verify. A copy sitting in the cache directory under a name
// an attacker can reach loses that property the moment it is written, because
// measuring a file and later reading it again are two reads of a mutable object.
// Overwriting the verified inode in place, without unlinking or renaming it,
// defeats any check made ahead of time.
//
// So the bytes are inflated somewhere nothing else can name, and nothing else
// is ever served. Verification time and use time refer to the same immutable
// object.
//
// The compressed section is read exactly once, teed through the digest and the
// inflater together, and the copy is discarded unless the digest matches. Reading
// it twice -- hashing it and then reopening or rewinding to inflate it -- would
// not be a verification at all: a descriptor does not freeze a file, so an
// attacker who rewrites the cache entry in place between the two passes has the
// first pass measure their absence and the second pass inflate their content,
// under the legitimate digest. That is the same check-time/use-time defect this
// function exists to close, one level further down.
//
// The cost is that a decompression bomb is inflated before it can be rejected.
// That is acceptable because it is bounded twice over -- openRegular caps the
// compressed input and limitio caps the inflated output -- so the work is
// bounded even when the bytes turn out to be forged. Rejecting earlier would
// mean reading the section twice, and that trade is not available.
//
// The caller owns the returned descriptor. Closing it releases the storage.
func (a *APKExpanded) VerifiedPackageData(want []byte) (*os.File, error) {
	gz, size, err := openRegular(a.PackageFile, maxCompressedSize(a.maxDataSize()))
	if err != nil {
		return nil, err
	}
	defer gz.Close()

	out, err := privateFile(filepath.Dir(a.PackageFile))
	if err != nil {
		return nil, err
	}

	// Bounded at the size openRegular measured on this descriptor. Without it the
	// copy runs to EOF, and a planted file can be extended after the size check
	// to make this read far more than was approved.
	h := sha256.New()
	src := io.TeeReader(io.LimitReader(gz, size), h)

	// Deliberately not returned yet. A section that fails to inflate has almost
	// always been tampered with rather than genuinely corrupted, and reporting
	// "gzip: invalid header" for that would name the symptom while the digest
	// below names the cause. Finishing the read first costs one bounded pass and
	// keeps the diagnosis accurate.
	inflateErr := a.inflate(src, out)

	// gzip stops at its trailer, so anything after it is still unread and still
	// covered by datahash. Pull it through the digest, or a section with trailing
	// bytes never matches. This also has to happen when inflation failed early,
	// or the digest covers only the prefix that was consumed.
	if _, err := io.Copy(io.Discard, src); err != nil {
		out.Close()
		return nil, fmt.Errorf("hashing %q: %w", a.PackageFile, err)
	}

	if gzSum := h.Sum(nil); !bytes.Equal(want, gzSum) {
		// Closing discards the copy: it is unlinked, so this is the only reference
		// and the storage goes with it.
		out.Close()
		return nil, fmt.Errorf("data hash mismatch: expected %x, got %x", want, gzSum)
	}

	// The bytes are authentic, so this is a real defect in a legitimate package
	// rather than a substitution.
	if inflateErr != nil {
		out.Close()
		return nil, inflateErr
	}

	if _, err := out.Seek(0, io.SeekStart); err != nil {
		out.Close()
		return nil, fmt.Errorf("rewinding the private copy of %q: %w", a.PackageFile, err)
	}

	// Tell IsValid not to look for this descriptor's name on disk: it has none.
	a.Lock()
	a.privateData = true
	a.Unlock()

	return out, nil
}

// inflate decompresses src into out, bounded by the configured decompressed-size
// limit.
func (a *APKExpanded) inflate(src io.Reader, out io.Writer) error {
	br := pooledBufioReader(src)
	defer readerPool.Put(br)

	zr, err := gzip.NewReader(br)
	if err != nil {
		return fmt.Errorf("parsing %q: %w", a.PackageFile, err)
	}
	defer zr.Close()

	if _, err := io.Copy(out, limitio.NewLimitedReaderWithDefault(zr, a.maxDataSize(), DefaultMaxDataSize)); err != nil {
		return fmt.Errorf("decompressing %q: %w", a.PackageFile, err)
	}
	return nil
}

// privateFile returns a descriptor for a file that nothing outside this process
// can reach, so the bytes written through it cannot change after they are
// verified.
//
// dir is preferred so the copy lands on the filesystem already sized for package
// data. A cache directory can legitimately be read-only, and a build over one
// must keep working, so that falls back to the system temp dir.
//
// THE STRENGTH OF THIS DEPENDS ON THE PLATFORM. anonymousFile has two
// implementations and they do not give the same guarantee. On Linux, O_TMPFILE
// never publishes a name, so there is no window and nothing to attack.
// Everywhere else -- darwin is a supported apko target -- and on Linux
// filesystems without O_TMPFILE, the only option is unlinkedTempFile, which has
// to create a name and unlink it; see the analysis of that window on
// unlinkedTempFile itself.
func privateFile(dir string) (*os.File, error) {
	f, err := anonymousFile(dir)
	if err == nil {
		return f, nil
	}

	f, fallbackErr := anonymousFile(os.TempDir())
	if fallbackErr != nil {
		return nil, fmt.Errorf("creating a private data file in %q (%w) or %q: %w",
			dir, err, os.TempDir(), fallbackErr)
	}
	return f, nil
}

// unlinkedTempFile creates a named temporary file, unlinks it, and returns the
// descriptor only if no other name for the inode survived. It is the weaker half
// of anonymousFile: the fallback for platforms and filesystems with no
// windowless primitive, and the only path outside Linux.
//
// The window between creating the name and unlinking it is exploitable rather
// than theoretical, and two distinct attacks live in it which are not equally
// defensible:
//
//   - Hardlink the name, keeping a second reference to the inode after the
//     unlink. Detectable: the link count is non-zero afterwards, so this
//     function checks it and refuses.
//   - Simply open the name for writing. The unlink then removes the only link,
//     the link count reads zero, the check passes, and the attacker still writes
//     through their descriptor into what this one serves. There is no portable
//     way to count the openers of an inode, so this cannot be detected at all.
//
// What saves the realistic case is ownership rather than either check.
// os.CreateTemp creates at mode 0600 owned by us, so a cache writer running as a
// *different* uid -- the shared-CI case this threat model is about -- cannot open
// it, and where /proc/sys/fs/protected_hardlinks is enabled they cannot hardlink
// a file they neither own nor can read either. That sysctl is not a kernel
// default: the kernel ships it off and distribution sysctl defaults turn it on,
// so a minimal container may not have it at all, leaving the link check above as
// the only thing standing between a different-uid attacker and a second
// reference. Note also that hardlinking needs write access to the containing
// directory rather than read access to the file, so 0600 alone does not prevent
// it. Against a *same-uid*
// attacker none of that holds: they can open it, and if it were created mode
// 0000 instead they own it and can chmod it back. No DAC arrangement helps,
// because they already have every privilege this process has -- they can ptrace
// it too, so the private copy was never the binding constraint for them.
//
// So: integrity holds here against a different-uid cache writer, and does not
// hold against a same-uid one. Closing that properly means verifying at
// consumption rather than ahead of it -- hashing the tar as it is read for
// install and abandoning the layer on mismatch -- which is a larger change than
// this.
func unlinkedTempFile(dir string) (*os.File, error) {
	f, err := os.CreateTemp(dir, ".apko-data-*")
	if err != nil {
		return nil, err
	}
	if err := os.Remove(f.Name()); err != nil && !os.IsNotExist(err) {
		f.Close()
		return nil, fmt.Errorf("unlinking %q: %w", f.Name(), err)
	}

	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		f.Close()
		return nil, fmt.Errorf("stat of %q: %w", f.Name(), err)
	}
	if st.Nlink != 0 {
		f.Close()
		return nil, fmt.Errorf("%q still has %d link(s) after being unlinked, so another process holds a reference to it",
			f.Name(), st.Nlink)
	}
	return f, nil
}

// maxDataSize is the configured decompressed-size limit for the data section, or
// the default when this APKExpanded was assembled without options. A negative
// limit means unlimited.
func (a *APKExpanded) maxDataSize() int64 {
	if a.opts != nil && a.opts.MaxDataSize != 0 {
		return a.opts.MaxDataSize
	}
	return DefaultMaxDataSize
}

// maxCompressedSize converts a decompressed-size limit into a bound on the
// compressed file. A limit of zero or less means unlimited, matching maxDataSize:
// an operator who asks for no cap on the inflated data is not asking for one on
// its compressed form either.
//
// The two numbers are not the same, and using one for the other rejects real
// packages: gzip expands incompressible input slightly, so a data section at
// exactly the limit produces a .tar.gz a little over it. Deflate's worst case is
// about five bytes per 16KiB block plus a small header, so a generous allowance
// stays far away from legitimate packages while still bounding the sparse
// multi-terabyte file this exists to stop.
//
// The allowance saturates rather than wrapping. Unchecked, a limit near MaxInt64
// overflows to a negative number, which reads as "unlimited" and silently
// disables the gate -- the failure mode a size gate must not have.
func maxCompressedSize(maxData int64) int64 {
	if maxData <= 0 {
		return 0
	}
	allowance := maxData/1000 + 4096
	if maxData > math.MaxInt64-allowance {
		return math.MaxInt64
	}
	return maxData + allowance
}

// openRegular opens path for reading, rejecting anything that is not a regular
// file of at most max bytes, and returns the size it approved. A max of zero
// means no size limit.
//
// The checks are made against the descriptor, not the path. Checking the path
// and then opening it resolves the name twice, and in a directory an attacker
// controls those can be two different objects: the type check passes on a
// regular file, and the open lands on the FIFO that replaced it, blocking
// forever. Opening non-blocking and inspecting the result closes that.
//
// The size is returned rather than just checked because the check is a moment in
// time: the file can still be extended afterwards, so callers must bound their
// reads by what was approved instead of reading to EOF.
func openRegular(path string, max int64) (*os.File, int64, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, 0, err
	}

	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, 0, fmt.Errorf("%q: not a regular file (mode %v)", path, fi.Mode())
	}
	if max > 0 && fi.Size() > max {
		f.Close()
		return nil, 0, fmt.Errorf("%q: %d bytes exceeds the %d byte limit", path, fi.Size(), max)
	}

	// O_NONBLOCK has no meaning for a regular file, and leaving it set would be
	// inherited by anything that later re-uses the descriptor's flags.
	if err := unix.SetNonblock(int(f.Fd()), false); err != nil {
		f.Close()
		return nil, 0, fmt.Errorf("%q: clearing O_NONBLOCK: %w", path, err)
	}
	return f, fi.Size(), nil
}

// dataReader rewinds gz and wraps it in a gzip reader bounded by the configured
// decompressed-size limit. The caller must close the returned closer.
func (a *APKExpanded) dataReader(gz *os.File) (io.Reader, io.Closer, error) {
	if _, err := gz.Seek(0, io.SeekStart); err != nil {
		return nil, nil, fmt.Errorf("rewinding %q: %w", a.PackageFile, err)
	}

	br := pooledBufioReader(gz)
	zr, err := gzip.NewReader(br)
	if err != nil {
		readerPool.Put(br)
		return nil, nil, fmt.Errorf("parsing %q: %w", a.PackageFile, err)
	}

	// Idempotent: returning a pooled reader twice would hand the same one to two
	// later callers.
	var done bool
	closer := closerFunc(func() error {
		if done {
			return nil
		}
		done = true
		err := zr.Close()
		readerPool.Put(br)
		return err
	})
	return limitio.NewLimitedReaderWithDefault(zr, a.maxDataSize(), DefaultMaxDataSize), closer, nil
}

type closerFunc func() error

func (c closerFunc) Close() error { return c() }
