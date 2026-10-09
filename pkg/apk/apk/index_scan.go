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

package apk

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/klauspost/compress/gzip"
	"go.opentelemetry.io/otel"

	"chainguard.dev/apko/pkg/limitio"
)

// ScanRepositoryIndex fetches the index of the repository at repoURL for arch,
// verifies its signature against keys exactly as GetRepositoryIndexes does,
// and then calls fn with each package record of the index, in index order.
// No fn call happens unless the signature verifies.
//
// Unlike GetRepositoryIndexes, it neither builds Packages nor caches anything,
// so its memory use is bounded by the size of the compressed index. A record
// is the raw text of one package stanza, each line terminated by "\n" and the
// whole followed by the blank separator line, so ParsePackageIndex parses it
// into a single Package, or into none when the stanza names no package (a
// stanza a whole-index parse drops too). The record is only valid until fn
// returns. As with ParsePackageIndex, a trailing stanza that is not
// terminated by a blank line is ignored; records are not otherwise
// validated. An archive with more than one APKINDEX member is rejected.
//
// repoURL is a plain repository URL or local path; "@tag" repository lines are
// not accepted. A non-nil error from fn stops the scan and is returned wrapped.
// The scan can also fail after fn has seen some records, as when the index
// exceeds the decompressed size limit or is malformed past them, so on any
// error the caller must discard every record it was given.
// The returned etag is an opaque token of the index's ETag, or "" when the
// server sent none or the repository is local.
//
// The options honored are those that affect fetching and verification:
// WithHTTPClient, WithIndexAuthenticator, WithIgnoreSignatures,
// WithIgnoreSignatureForIndexes and WithIndexDecompressedMaxSize.
func ScanRepositoryIndex(ctx context.Context, repoURL string, keys map[string][]byte, arch string, fn func(record []byte) error, options ...IndexOption) (etag string, err error) {
	ctx, span := otel.Tracer("go-apk").Start(ctx, "ScanRepositoryIndex")
	defer span.End()

	opts := &indexOpts{}
	for _, opt := range options {
		opt(opts)
	}
	if opts.httpClient == nil {
		opts.httpClient = http.DefaultClient
	}

	u := IndexURL(repoURL, arch)
	var b []byte
	if strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "http://") {
		b, etag, err = fetchRepositoryIndex(ctx, u, "", opts)
	} else {
		b, err = os.ReadFile(u)
	}
	if err != nil {
		return "", fmt.Errorf("fetching %s: %w", redact(u), err)
	}

	if err := verifyIndexSignature(ctx, u, keys, arch, b, opts); err != nil {
		return "", fmt.Errorf("verifying %s: %w", redact(u), err)
	}
	if err := scanIndexArchive(bytes.NewReader(b), opts.indexDecompressedMaxSize, fn); err != nil {
		return "", fmt.Errorf("scanning %s: %w", redact(u), err)
	}
	return etag, nil
}

// scanIndexArchive calls fn with each record of the APKINDEX member of the
// gzipped tar archive r, accepting the same members IndexFromArchive does.
//
// An archive with more than one APKINDEX member is rejected, though
// IndexFromArchive keeps the last: fn has seen the earlier members' records
// by the time a later one turns up, and holding them back would cost the
// memory bound the scan exists for.
func scanIndexArchive(r io.Reader, maxSize int64, fn func(record []byte) error) error {
	gzipReader, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(limitio.NewLimitedReaderWithDefault(gzipReader, maxSize, DefaultMaxAPKIndexDecompressedSize))
	seenIndex := false
	for {
		hdr, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}

		switch {
		case hdr.Name == apkIndexFilename:
			if seenIndex {
				return fmt.Errorf("more than one %s found in APKINDEX", apkIndexFilename)
			}
			seenIndex = true
			if err := scanIndexRecords(tarReader, fn); err != nil {
				return err
			}
		case hdr.Name == descriptionFilename, strings.HasPrefix(hdr.Name, ".SIGN."):
			// The tar reader skips unread member data on Next.
		default:
			return fmt.Errorf("unexpected file found in APKINDEX: %s", hdr.Name)
		}
	}
}

// scanIndexRecords splits a plain APKINDEX into records, reusing one buffer.
// Its line handling matches ParsePackageIndex.
func scanIndexRecords(r io.Reader, fn func(record []byte) error) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 16*1024), 1024*1024)

	var record []byte
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) != 0 {
			record = append(record, line...)
			record = append(record, '\n')
			continue
		}
		if len(record) == 0 {
			continue
		}
		record = append(record, '\n')
		if err := fn(record); err != nil {
			return err
		}
		record = record[:0]
	}
	return scanner.Err()
}
