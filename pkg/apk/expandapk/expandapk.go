// THIS FILE IS AN EXACT DUPLICATE OF STUFF IN ALPINE-GO!
// Unfortunately, all of that is package-private rather than public,
// so we are duplicating it here. As soon as we can upstream this entire impl,
// this duplicate file goes away!

//nolint:all
package expandapk

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"chainguard.dev/apko/pkg/apk/internal/tarfs"
	"github.com/klauspost/compress/gzip"

	"go.opentelemetry.io/otel"
)

var slicePool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 1<<20)
	},
}

func pooledSlice() []byte {
	return slicePool.Get().([]byte)
}

var readerPool = sync.Pool{
	New: func() interface{} {
		return bufio.NewReaderSize(nil, 1<<20)
	},
}

func pooledBufioReader(r io.Reader) *bufio.Reader {
	br := readerPool.Get().(*bufio.Reader)
	br.Reset(r)
	return br
}

var writerPool = sync.Pool{
	New: func() interface{} {
		return bufio.NewWriterSize(nil, 1<<20)
	},
}

func pooledBufioWriter(w io.Writer) *bufio.Writer {
	bw := writerPool.Get().(*bufio.Writer)
	bw.Reset(w)
	return bw
}

// APKExpanded contains information about and reference to an expanded APK package.
// Close() deletes all temporary files and directories created during the expansion process.
type APKExpanded struct {
	// The size in bytes of the entire apk (sum of all tar.gz file sizes)
	Size int64

	// Whether or not the apk contains a signature
	// Note: currently unused
	Signed bool

	// The temporary parent directory containing all exploded .tar/.tar.gz contents
	tempDir string

	// The package signature filename (a.k.a. ".SIGN...") in tar.gz format
	SignatureFile string

	// The control data filename (a.k.a. ".PKGINFO") in tar.gz format
	ControlFile string

	// The package data filename in .tar.gz format
	PackageFile string

	// The package data filename in .tar format.
	TarFile string

	// Expose ControlFile as an indexed FS implementation.
	ControlFS *tarfs.FS

	// Exposes TarFile as an indexed FS implementation.
	TarFS *tarfs.FS

	ControlHash   []byte
	PackageHash   []byte
	SignatureHash []byte

	ControlSize   int64
	PackageSize   int64
	SignatureSize int64

	sync.Mutex
	controlData []byte
}

func (a *APKExpanded) ControlData() ([]byte, error) {
	a.Lock()
	defer a.Unlock()
	if a.controlData == nil {
		rc, err := os.Open(a.ControlFile)
		if err != nil {
			return nil, err
		}
		defer rc.Close()

		zr, err := gzip.NewReader(rc)
		if err != nil {
			return nil, err
		}

		a.controlData, err = io.ReadAll(zr)
		if err != nil {
			return nil, err
		}
	}

	return a.controlData, nil
}

func (a *APKExpanded) PackageData() (*os.File, error) {
	uf, err := os.Open(a.TarFile)
	if err == nil {
		return uf, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("opening package data file: %w", err)
	}

	// Handle old caches without the uncompressed file.
	f, err := os.Open(a.PackageFile)
	if err != nil {
		return nil, fmt.Errorf("opening %q: %w", a.PackageFile, err)
	}
	defer f.Close()

	br := pooledBufioReader(f)
	defer readerPool.Put(br)

	zr, err := gzip.NewReader(br)
	if err != nil {
		return nil, fmt.Errorf("parsing %q: %w", a.PackageFile, err)
	}

	uf, err = os.Create(a.TarFile)
	if err != nil {
		return nil, fmt.Errorf("opening tar file %q: %w", a.TarFile, err)
	}

	buf := pooledSlice()
	defer slicePool.Put(buf)

	if _, err := io.CopyBuffer(uf, zr, buf); err != nil {
		return nil, fmt.Errorf("decompressing %q: %w", a.PackageFile, err)
	}

	if err := uf.Close(); err != nil {
		return nil, fmt.Errorf("closing %q: %w", a.TarFile, err)
	}

	return os.Open(a.TarFile)
}

func (a *APKExpanded) APK() (io.ReadCloser, error) {
	rs := []io.Reader{}
	cs := []io.Closer{}

	for _, fn := range []string{a.SignatureFile, a.ControlFile, a.PackageFile} {
		if fn != "" {
			f, err := os.Open(fn)
			if err != nil {
				return nil, err
			}
			rs = append(rs, f)
			cs = append(cs, f)
		}
	}

	return &multiReadCloser{
		r:       io.MultiReader(rs...),
		closers: cs,
	}, nil
}

type multiReadCloser struct {
	r       io.Reader
	closers []io.Closer
}

func (m *multiReadCloser) Read(p []byte) (int, error) {
	return m.r.Read(p)
}

func (m *multiReadCloser) Close() error {
	errs := make([]error, len(m.closers))
	for i, closer := range m.closers {
		errs[i] = closer.Close()
	}
	return errors.Join(errs...)
}

func (a *APKExpanded) Close() error {
	errs := []error{}

	if a.tempDir != "" {
		errs = append(errs, os.RemoveAll(a.tempDir))
	}

	return errors.Join(errs...)
}

// An implementation of io.Writer designed specifically for use in the expandApk() method.
// This wraps os.File, and allows the same writer to be used to write across multiple files.
// The Next() method can be called at any point, which increments "streamId" and sets the
// underlying file to a new file with name in the form <parentDir>/<baseName>-<streamId>.<ext>
type expandApkWriter struct {
	parentDir  string
	baseName   string
	ext        string
	streamId   int
	maxStreams int
	f          *os.File
}

func newExpandApkWriter(parentDir string, baseName string, ext string) (*expandApkWriter, error) {
	sw := expandApkWriter{
		parentDir:  parentDir,
		baseName:   baseName,
		ext:        ext,
		streamId:   -1,
		maxStreams: 2,
	}
	return &sw, nil
}

func (sw *expandApkWriter) Write(p []byte) (int, error) {
	i, err := sw.f.Write(p)
	if err != nil {
		err = fmt.Errorf("expandApkWriter.Write: %w", err)
	}
	return i, err
}

var _ io.Writer = (*expandApkWriter)(nil)

var errExpandApkWriterMaxStreams = errors.New("expandApkWriter max streams reached")

func (w *expandApkWriter) Next() error {
	if w.f != nil {
		if err := w.CloseFile(); err != nil {
			return fmt.Errorf("expandApkWriter.Next error 1: %v", err)
		}
	}

	// When the first stream is done writing, open up the tarball and
	// determine if it is a signature. If so, bump the max streams from 2 to 3.
	// The final stream should contain the entirety of the actual package contents
	if w.streamId == 0 {
		f, err := os.Open(w.f.Name())
		if err != nil {
			return fmt.Errorf("expandApkWriter.Next error 2: %v", err)
		}
		defer f.Close()
		gzipRead, err := gzip.NewReader(f)
		if err != nil {
			return fmt.Errorf("expandApkWriter.Next error 3: %v", err)
		}
		defer gzipRead.Close()
		tarRead := tar.NewReader(gzipRead)
		hdr, err := tarRead.Next()
		if err != nil {
			return fmt.Errorf("expandApkWriter.Next error 4: %v", err)
		}
		if strings.HasPrefix(hdr.Name, ".SIGN.") {
			w.maxStreams = 3
		}
	}

	w.streamId++
	p := fmt.Sprintf("%s-%d.%s", filepath.Join(w.parentDir, w.baseName), w.streamId, w.ext)
	file, err := os.Create(p)
	if err != nil {
		return fmt.Errorf("expandApkWriter.Next error 5: %w", err)
	}
	w.f = file

	// At this point, we should have created the final tar.gz file,
	// so inform the consumer of this method to speed up the read
	// by returning this specific error
	if w.streamId+1 >= w.maxStreams {
		return errExpandApkWriterMaxStreams
	}

	return nil
}

func (w expandApkWriter) CurrentName() string {
	return w.f.Name()
}

func (w expandApkWriter) CloseFile() error {
	return w.f.Close()
}

// An implementation of io.Reader designed specifically for use in the expandApk() method.
// When used in combination with the expandApkWrier (based on os.File) in a io.TeeReader,
// the Go stdlib optimizes the write, causing readahead, even if the actual stream size
// is less than the size of the incoming buffer. To fix this, the Read() method on this
// Reader has been modified to read only a single byte at a time to workaround the issue.
type expandApkReader struct {
	io.Reader
	fast bool
}

func newExpandApkReader(r io.Reader) *expandApkReader {
	return &expandApkReader{
		Reader: r,
		fast:   false,
	}
}

func (r *expandApkReader) Read(b []byte) (int, error) {
	if r.fast {
		return r.Reader.Read(b)
	}
	buf := make([]byte, 1)
	n, err := r.Reader.Read(buf)
	if err != nil && err != io.EOF {
		err = fmt.Errorf("expandApkReader.Read: %w", err)
	} else {
		b[0] = buf[0]
	}
	return n, err
}

func (r *expandApkReader) EnableFastRead() {
	r.fast = true
}

// ExpandAPK given a ready to an apk stream, normally a tar stream with gzip compression,
// expand it into its components.
//
// An apk is split into either 2 or 3 file streams (2 for unsigned packages, 3 for signed).
//
// For more info, see https://wiki.alpinelinux.org/wiki/Apk_spec:
//
//	"APK v2 packages contain two tar segments followed by a tarball each in their
//	own gzip stream (3 streams total). These streams contain the package signature,
//	control data, and package data"
//
// Returns an APKExpanded struct containing references to the file. You *must* call APKExpanded.Close()
// when finished to clean up the various files.
func ExpandApk(ctx context.Context, source io.Reader, cacheDir string) (*APKExpanded, error) {
	ctx, span := otel.Tracer("go-apk").Start(ctx, "ExpandApk")
	defer span.End()

	dir, err := os.MkdirTemp(cacheDir, "expand-apk")
	if err != nil {
		return nil, err
	}

	sw, err := newExpandApkWriter(dir, "stream", "tar.gz")
	if err != nil {
		return nil, fmt.Errorf("expandApk error 1: %w", err)
	}
	exR := newExpandApkReader(source)
	tr := io.TeeReader(exR, sw)
	var gzi *gzip.Reader
	gzipStreams := []string{}
	hashes := [][]byte{}
	maxStreamsReached := false
	for {
		// Control section uses sha1.
		var h hash.Hash = sha1.New() //nolint:gosec // this is what apk tools is using

		if err := sw.Next(); err != nil {
			if err == errExpandApkWriterMaxStreams {
				maxStreamsReached = true
				exR.EnableFastRead()

				// Data section uses sha256.
				h = sha256.New()
			} else {
				return nil, fmt.Errorf("expandApk error 5: %w", err)
			}
		}

		hr := io.TeeReader(tr, h)

		if gzi == nil {
			gzi, err = gzip.NewReader(hr)
		} else {
			err = gzi.Reset(hr)
		}

		if err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("creating gzip reader: %w", err)
		}

		if !maxStreamsReached {
			gzi.Multistream(false)

			if _, err := io.Copy(io.Discard, gzi); err != nil {
				return nil, fmt.Errorf("expandApk error 3: %w", err)
			}

			hashes = append(hashes, h.Sum(nil))
			gzipStreams = append(gzipStreams, sw.CurrentName())
		} else {
			// While we verify checksums, also tee the tar to a separate file.
			tarfilename := strings.TrimSuffix(sw.CurrentName(), ".gz")
			tarfile, err := os.Create(tarfilename)
			if err != nil {
				return nil, fmt.Errorf("opening tar file: %w", err)
			}
			bw := pooledBufioWriter(tarfile)
			defer writerPool.Put(bw)

			tr := io.TeeReader(gzi, bw)

			if err := checkSums(ctx, tr); err != nil {
				return nil, fmt.Errorf("checking sums: %w", err)
			}
			if _, err := io.Copy(io.Discard, tr); err != nil {
				return nil, fmt.Errorf("expandApk error 3: %w", err)
			}

			if err := bw.Flush(); err != nil {
				return nil, fmt.Errorf("flushing tarfile: %w", err)
			}

			if err := tarfile.Close(); err != nil {
				return nil, fmt.Errorf("closing tarfile: %w", err)
			}
			gzipStreams = append(gzipStreams, sw.CurrentName())
			hashes = append(hashes, h.Sum(nil))
			break
		}
	}

	if err := gzi.Close(); err != nil {
		return nil, fmt.Errorf("expandApk error 6: %w", err)
	}
	if err := sw.CloseFile(); err != nil {
		return nil, fmt.Errorf("expandApk error 7: %w", err)
	}

	numGzipStreams := len(gzipStreams)

	// Calculate the total size of the apk (combo of all streams)
	totalSize := int64(0)
	sizes := []int64{}
	for _, s := range gzipStreams {
		info, err := os.Stat(s)
		if err != nil {
			return nil, fmt.Errorf("expandApk error 18: %w", err)
		}
		totalSize += info.Size()
		sizes = append(sizes, info.Size())
	}

	var signatureIndex int
	var controlDataIndex int
	var packageIndex int

	switch numGzipStreams {
	case 3:
		signatureIndex = 0
		controlDataIndex = 1
		packageIndex = 2
	case 2:
		signatureIndex = -1
		controlDataIndex = 0
		packageIndex = 1
	default:
		return nil, fmt.Errorf("invalid number of tar streams: %d", numGzipStreams)
	}
	signed := signatureIndex >= 0

	expanded := APKExpanded{
		tempDir:     dir,
		Signed:      signed,
		Size:        totalSize,
		ControlFile: gzipStreams[controlDataIndex],
		ControlHash: hashes[controlDataIndex],
		ControlSize: sizes[controlDataIndex],
		PackageFile: gzipStreams[packageIndex],
		PackageHash: hashes[packageIndex],
		PackageSize: sizes[controlDataIndex],
	}
	if signed {
		expanded.SignatureFile = gzipStreams[signatureIndex]
		expanded.SignatureHash = hashes[signatureIndex]
		expanded.SignatureSize = sizes[signatureIndex]
	}

	control, err := expanded.ControlData()
	if err != nil {
		return nil, err
	}

	expanded.ControlFS, err = tarfs.New(bytes.NewReader(control), int64(len(control)))
	if err != nil {
		return nil, fmt.Errorf("indexing %q: %w", expanded.ControlFile, err)
	}

	expanded.TarFile = strings.TrimSuffix(expanded.PackageFile, ".gz")

	data, err := expanded.PackageData()
	if err != nil {
		return nil, err
	}
	info, err := data.Stat()
	if err != nil {
		return nil, err
	}

	// TODO: We could overlap this with checkSums.
	expanded.TarFS, err = tarfs.New(data, info.Size())
	if err != nil {
		return nil, fmt.Errorf("indexing %q: %w", expanded.TarFile, err)
	}

	return &expanded, nil
}

func checkSums(ctx context.Context, r io.Reader) error {
	ctx, span := otel.Tracer("go-apk").Start(ctx, "checkSums")
	defer span.End()

	tr := tar.NewReader(r)

	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}

		if header.Typeflag != tar.TypeReg {
			continue
		}

		checksum, err := checksumFromHeader(header)
		if err != nil {
			return err
		}

		// If for some reason this is missing, ignore it. We will calculate it later.
		if checksum == nil {
			continue
		}

		w := sha1.New() //nolint:gosec // this is what apk tools is using

		if _, err := io.Copy(w, tr); err != nil {
			return fmt.Errorf("hashing %s: %w", header.Name, err)
		}

		if want, got := checksum, w.Sum(nil); !bytes.Equal(want, got) {
			return fmt.Errorf("checksum mismatch: %s header was %x, computed %x", header.Name, want, got)
		}
	}

	return nil
}
