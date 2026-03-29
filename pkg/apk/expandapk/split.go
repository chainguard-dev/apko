package expandapk

import (
	"archive/tar"
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/klauspost/compress/gzip"

	"chainguard.dev/apko/pkg/limitio"
)

// Split takes an APK reader and splits it into its constituent parts.
//
// If the length of the returned slice is 3, the first part is the signature section.
// If the length of the returned slice is 2, the first part is the control section.
// The last part is the data section.
//
// These values are the compressed gzip streams, and should be decompressed before use.
//
// The signature and control sections are buffered in memory, while the data section is streamed
// from the input reader.
func Split(source io.Reader) ([]io.Reader, error) {
	return SplitWithOptions(source)
}

// SplitWithOptions is like Split but accepts functional options to configure
// size limits for APK sections.
func SplitWithOptions(source io.Reader, opts ...Option) ([]io.Reader, error) {
	options := DefaultOptions()
	for _, opt := range opts {
		if err := opt(options); err != nil {
			return nil, fmt.Errorf("applying option: %w", err)
		}
	}

	return splitWithOptions(source, options)
}

func splitWithOptions(source io.Reader, options *Options) ([]io.Reader, error) {
	parts := []io.Reader{}

	br := bufio.NewReader(source)

	buf := bytes.Buffer{}
	tee := &teeByteReader{r: br, w: &buf}

	gzi, err := gzip.NewReader(tee)
	if err != nil {
		return nil, fmt.Errorf("creating gzip reader: %w", err)
	}
	gzi.Multistream(false)

	tr := tar.NewReader(gzi)
	hdr, err := tr.Next()
	if err != nil {
		return nil, fmt.Errorf("reading first tar header: %w", err)
	}

	// Handle optional signature section.
	if strings.HasPrefix(hdr.Name, ".SIGN.") {
		if _, err := io.Copy(io.Discard, limitio.NewLimitedReaderWithDefault(gzi, options.MaxControlSize, DefaultMaxControlSize)); err != nil {
			return nil, fmt.Errorf("copying signature stream: %w", err)
		}

		parts = append(parts, bytes.NewReader(buf.Bytes()))

		// Use a new buffer for the control section.
		buf = bytes.Buffer{}
		tee.w = &buf

		if err := gzi.Reset(tee); err != nil {
			return nil, fmt.Errorf("resetting gzip reader after signature: %w", err)
		}
		gzi.Multistream(false)
	}

	// There should always be a control section.
	if _, err := io.Copy(io.Discard, limitio.NewLimitedReaderWithDefault(gzi, options.MaxControlSize, DefaultMaxControlSize)); err != nil {
		return nil, fmt.Errorf("copying control stream: %w", err)
	}

	parts = append(parts, bytes.NewReader(buf.Bytes()))

	if err := gzi.Close(); err != nil {
		return nil, fmt.Errorf("closing gzip reader: %w", err)
	}

	// And the rest is the data section.
	dataReader := limitio.NewLimitedReaderWithDefault(br, options.MaxDataSize, DefaultMaxDataSize)
	parts = append(parts, dataReader)

	return parts, nil
}

// like io.TeeReader but also implements io.ByteReader for gzip.
//
// From gzip.Reader.Multistream:
//
// > If the underlying reader implements io.ByteReader,
// > it will be left positioned just after the gzip stream.
type teeByteReader struct {
	r interface {
		io.Reader
		io.ByteReader
	}

	w interface {
		io.Writer
		io.ByteWriter
	}
}

func (t *teeByteReader) ReadByte() (byte, error) {
	c, err := t.r.ReadByte()
	if err := t.w.WriteByte(c); err != nil {
		return c, err
	}
	return c, err
}

func (t *teeByteReader) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if n > 0 {
		if n, err := t.w.Write(p[:n]); err != nil {
			return n, err
		}
	}
	return n, err
}
