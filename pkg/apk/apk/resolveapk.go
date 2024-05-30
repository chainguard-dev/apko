//nolint:all
package apk

import (
	"archive/tar"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"strconv"
	"strings"

	"github.com/klauspost/compress/gzip"

	"go.opentelemetry.io/otel"
)

// An implementation of io.Reader designed specifically for use in the resolveApk() method.
// When used in combination with the expandApkWrier (based on os.File) in a io.TeeReader,
// the Go stdlib optimizes the write, causing readahead, even if the actual stream size
// is less than the size of the incoming buffer. To fix this, the Read() method on this
// Reader has been modified to read only a single byte at a time to workaround the issue.
type noReadAheadApkReader struct {
	io.Reader
}

func newNoReadAheadApkReader(r io.Reader) *noReadAheadApkReader {
	return &noReadAheadApkReader{
		Reader: r,
	}
}

func (r *noReadAheadApkReader) Read(b []byte) (int, error) {
	buf := make([]byte, 1)
	n, err := r.Reader.Read(buf)
	if err != nil && err != io.EOF {
		err = fmt.Errorf("expandApkReader.Read: %w", err)
	} else {
		b[0] = buf[0]
	}
	return n, err
}

type APKResolved struct {
	Package *RepositoryPackage

	SignatureSize int
	SignatureHash []byte

	ControlSize int
	ControlHash []byte

	DataSize int
	DataHash []byte
}

type countingWriter struct {
	bytesWritten int
}

func (r *countingWriter) Write(p []byte) (n int, err error) {
	r.bytesWritten += len(p)
	return n, nil
}

func ResolveApk(ctx context.Context, source io.Reader) (*APKResolved, error) {
	ctx, span := otel.Tracer("go-apk").Start(ctx, "ResolveApk")
	defer span.End()

	gzipStreamSizes := make([]int, 3)
	hashes := make([][]byte, 3)
	maxStreams := 2
	streamId := 0
	controlIdx := 0
	signed := false

	var gzi *gzip.Reader
	cr := &countingWriter{}
	tr := io.TeeReader(source, cr)
	norar := newNoReadAheadApkReader(tr)

	for {
		var h hash.Hash = sha1.New() //nolint:gosec

		hr := io.TeeReader(norar, h)

		var err error

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
		gzi.Multistream(false)

		if streamId == 0 {
			tr := tar.NewReader(gzi)
			hdr, err := tr.Next()
			if err != nil {
				return nil, fmt.Errorf("ResolveApk error 1: %v", err)
			}
			if strings.HasPrefix(hdr.Name, ".SIGN.") {
				maxStreams = 3
				controlIdx = 1
				signed = true
			}
		} else if controlIdx == streamId {
			mapping, err := controlValue(gzi, "datahash", "size")
			if err != nil {
				return nil, fmt.Errorf("reading datahash and size from control: %w", err)
			}

			if sizes, ok := mapping["size"]; !ok {
				return nil, fmt.Errorf("reading size from control: %w", err)
			} else if len(sizes) != 1 {
				return nil, fmt.Errorf("saw %d size values", len(sizes))
			} else if size, err := strconv.Atoi(sizes[0]); err != nil {
				return nil, fmt.Errorf("parsing size from  control: %w", err)
			} else {
				gzipStreamSizes[maxStreams-1] = size
			}

			if datahashes, ok := mapping["datahash"]; !ok {
				return nil, fmt.Errorf("reading datahash from control: %w", err)
			} else if len(datahashes) != 1 {
				return nil, fmt.Errorf("saw %d datahash values", len(datahashes))
			} else if hash, err := hex.DecodeString(datahashes[0]); err != nil {
				return nil, fmt.Errorf("reading datahash from control: %w", err)
			} else {
				hashes[maxStreams-1] = hash
			}
		}

		if streamId <= controlIdx {
			if _, err := io.Copy(io.Discard, gzi); err != nil {
				return nil, fmt.Errorf("ResolveApk error 2: %v", err)
			}

			hashes[streamId] = h.Sum(nil)
			gzipStreamSizes[streamId] = cr.bytesWritten
		} else {
			gzi.Close()
			break
		}

		streamId++
	}

	resolved := &APKResolved{
		SignatureSize: 0,
		ControlSize:   gzipStreamSizes[controlIdx],
		ControlHash:   hashes[controlIdx],
		DataSize:      gzipStreamSizes[controlIdx+1],
		DataHash:      hashes[controlIdx+1],
	}

	if signed {
		resolved.SignatureSize = gzipStreamSizes[0]
		resolved.SignatureHash = hashes[0]
	}

	return resolved, nil
}
