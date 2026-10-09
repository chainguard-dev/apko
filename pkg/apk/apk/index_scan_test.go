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
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/gzip"
	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/apk/auth"
	"chainguard.dev/apko/pkg/limitio"
)

// scanAll scans an index and returns copies of its records.
func scanAll(t *testing.T, repoURL string, keys map[string][]byte, opts ...IndexOption) ([][]byte, string, error) {
	t.Helper()
	var records [][]byte
	etag, err := ScanRepositoryIndex(t.Context(), repoURL, keys, "x86_64", func(record []byte) error {
		records = append(records, bytes.Clone(record))
		return nil
	}, opts...)
	return records, etag, err
}

// requireRecordsMatchIndex checks that records parse one by one into exactly
// the packages a whole-index parse of archive produces.
func requireRecordsMatchIndex(t *testing.T, records [][]byte, archive []byte) {
	t.Helper()
	index, err := IndexFromArchive(io.NopCloser(bytes.NewReader(archive)))
	require.NoError(t, err)
	require.Len(t, records, len(index.Packages))
	for i, record := range records {
		pkgs, err := ParsePackageIndex(bytes.NewReader(record))
		require.NoError(t, err)
		require.Len(t, pkgs, 1, "record %d:\n%s", i, record)
		require.Equal(t, index.Packages[i], pkgs[0])
	}
}

type testIndexKey struct {
	name string
	priv *rsa.PrivateKey
	pub  []byte
}

func newTestIndexKey(t *testing.T) testIndexKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	return testIndexKey{
		name: "scan-test.rsa.pub",
		priv: priv,
		pub:  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}),
	}
}

// unsignedTestIndex renders packages as an unsigned APKINDEX.tar.gz.
func unsignedTestIndex(t *testing.T, pkgs []*Package) []byte {
	t.Helper()
	archive, err := ArchiveFromIndex(&APKIndex{Description: "scan test", Packages: pkgs})
	require.NoError(t, err)
	b, err := io.ReadAll(archive)
	require.NoError(t, err)
	return b
}

// signTestIndex prepends an apk signature segment over index, signed by key.
func signTestIndex(t *testing.T, key testIndexKey, index []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(index)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key.priv, crypto.SHA256, digest[:])
	require.NoError(t, err)

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name: ".SIGN.RSA256." + key.name,
		Mode: 0o644,
		Size: int64(len(sig)),
	}))
	_, err = tw.Write(sig)
	require.NoError(t, err)
	// Flush, not Close: the signature segment must not end the tar stream
	// that continues into the index segment.
	require.NoError(t, tw.Flush())
	require.NoError(t, gw.Close())
	return append(buf.Bytes(), index...)
}

func scanTestPackages(n int) []*Package {
	pkgs := make([]*Package, 0, n)
	for i := range n {
		pkgs = append(pkgs, &Package{
			Name:         fmt.Sprintf("pkg-%d", i),
			Version:      "1.0-r0",
			Arch:         "x86_64",
			Description:  "scan test package",
			Checksum:     []byte(fmt.Sprintf("checksum-%011d", i)),
			Dependencies: []string{"so:libc.so.6", fmt.Sprintf("dep-%d", i)},
			Provides:     []string{fmt.Sprintf("cmd:tool-%d=1.0-r0", i)},
		})
	}
	return pkgs
}

// serveIndex serves body as the x86_64 index, optionally with an ETag and
// requiring basic auth, and counts requests.
func serveIndex(t *testing.T, body []byte, etag string, user, pass string) (*httptest.Server, *int) {
	t.Helper()
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if user != "" {
			if u, p, ok := r.BasicAuth(); !ok || u != user || p != pass {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
		if r.URL.Path != "/x86_64/APKINDEX.tar.gz" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if etag != "" {
			w.Header().Set("ETag", `"`+etag+`"`)
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv, &requests
}

func TestScanRepositoryIndexVerified(t *testing.T) {
	key := newTestIndexKey(t)
	index := unsignedTestIndex(t, scanTestPackages(50))
	signed := signTestIndex(t, key, index)
	srv, requests := serveIndex(t, signed, "v1", "", "")

	records, etag, err := scanAll(t, srv.URL, map[string][]byte{key.name: key.pub}, WithHTTPClient(srv.Client()))
	require.NoError(t, err)
	requireRecordsMatchIndex(t, records, signed)
	require.Len(t, records, 50)
	require.Equal(t, 1, *requests, "scan should need a single GET")

	resp := &http.Response{Header: http.Header{"Etag": []string{`"v1"`}}}
	want, _ := etagFromResponse(resp)
	require.Equal(t, want, etag)
}

func TestScanRepositoryIndexNoETag(t *testing.T) {
	index := unsignedTestIndex(t, scanTestPackages(3))
	srv, _ := serveIndex(t, index, "", "", "")

	records, etag, err := scanAll(t, srv.URL, nil, WithHTTPClient(srv.Client()), WithIgnoreSignatures(true))
	require.NoError(t, err)
	require.Len(t, records, 3)
	require.Empty(t, etag)
}

func TestScanRepositoryIndexRejectsBeforeYielding(t *testing.T) {
	key := newTestIndexKey(t)
	other := newTestIndexKey(t)
	index := unsignedTestIndex(t, scanTestPackages(5))
	tampered := unsignedTestIndex(t, append(scanTestPackages(5), &Package{Name: "evil", Version: "1-r0"}))

	signed := signTestIndex(t, key, index)
	// Keep the signature segment, swap in a different index segment.
	swapped := append(bytes.Clone(signed[:len(signed)-len(index)]), tampered...)

	for _, tc := range []struct {
		name string
		body []byte
		keys map[string][]byte
		opts []IndexOption
	}{{
		name: "wrong key",
		body: signed,
		keys: map[string][]byte{key.name: other.pub},
	}, {
		name: "tampered index",
		body: swapped,
		keys: map[string][]byte{key.name: key.pub},
	}, {
		name: "unsigned",
		body: index,
		keys: map[string][]byte{key.name: key.pub},
	}, {
		name: "unknown key name",
		body: signed,
		keys: map[string][]byte{"someone-else.rsa.pub": key.pub},
	}, {
		name: "no keys",
		body: signed,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := serveIndex(t, tc.body, "", "", "")
			calls := 0
			_, err := ScanRepositoryIndex(t.Context(), srv.URL, tc.keys, "x86_64", func([]byte) error {
				calls++
				return nil
			}, WithHTTPClient(srv.Client()))
			require.Error(t, err)
			require.Zero(t, calls, "fn called before the signature was verified")
		})
	}
}

func TestScanRepositoryIndexIgnoreSignatureForIndexes(t *testing.T) {
	index := unsignedTestIndex(t, scanTestPackages(2))
	srv, _ := serveIndex(t, index, "", "", "")

	records, _, err := scanAll(t, srv.URL, nil, WithHTTPClient(srv.Client()), WithIgnoreSignatureForIndexes(srv.URL))
	require.NoError(t, err)
	require.Len(t, records, 2)
}

func TestScanRepositoryIndexAuth(t *testing.T) {
	index := unsignedTestIndex(t, scanTestPackages(2))
	srv, _ := serveIndex(t, index, "", testUser, testPass)
	host := strings.TrimPrefix(srv.URL, "http://")

	records, _, err := scanAll(t, srv.URL, nil, WithHTTPClient(srv.Client()), WithIgnoreSignatures(true),
		WithIndexAuthenticator(auth.StaticAuth(host, testUser, testPass)))
	require.NoError(t, err)
	require.Len(t, records, 2)

	records, _, err = scanAll(t, srv.URL, nil, WithHTTPClient(srv.Client()), WithIgnoreSignatures(true),
		WithIndexAuthenticator(auth.StaticAuth(host, "baduser", "badpass")))
	require.ErrorContains(t, err, "401")
	require.Empty(t, records)
}

func TestScanRepositoryIndexMaxSize(t *testing.T) {
	index := unsignedTestIndex(t, scanTestPackages(200))
	srv, _ := serveIndex(t, index, "", "", "")

	records, _, err := scanAll(t, srv.URL, nil, WithHTTPClient(srv.Client()), WithIgnoreSignatures(true),
		WithIndexDecompressedMaxSize(1024))
	var limitErr *limitio.SizeLimitExceededError
	require.ErrorAs(t, err, &limitErr)
	// The limit is hit mid-scan, after fn has seen records the caller must
	// discard.
	require.NotEmpty(t, records)
}

func TestScanRepositoryIndexStopsOnError(t *testing.T) {
	index := unsignedTestIndex(t, scanTestPackages(10))
	srv, _ := serveIndex(t, index, "", "", "")

	stop := errors.New("stop")
	calls := 0
	_, err := ScanRepositoryIndex(t.Context(), srv.URL, nil, "x86_64", func([]byte) error {
		calls++
		return stop
	}, WithHTTPClient(srv.Client()), WithIgnoreSignatures(true))
	require.ErrorIs(t, err, stop)
	require.Equal(t, 1, calls)
}

func TestScanRepositoryIndexLocal(t *testing.T) {
	// A real, signed Alpine index: exercises provides, install-if and the
	// legacy RSA/SHA-1 signature type.
	archive, err := os.ReadFile("testdata/alpine-317/APKINDEX.tar.gz")
	require.NoError(t, err)
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "x86_64"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "x86_64", "APKINDEX.tar.gz"), archive, 0o600))

	keys := map[string][]byte{}
	for name, key := range testKeys {
		keys[name] = []byte(key)
	}
	records, etag, err := scanAll(t, dir, keys)
	require.NoError(t, err)
	require.Empty(t, etag)
	requireRecordsMatchIndex(t, records, archive)
}

func TestScanIndexRecordsMatchesParsePackageIndex(t *testing.T) {
	for _, tc := range []struct {
		name    string
		index   string
		unnamed int
	}{{
		name:  "terminated",
		index: "C:Q1YWFhYQ==\nP:a\nV:1\n\nC:Q1YmJiYg==\nP:b\nV:2\no:b\np:x=1 y\n\n",
	}, {
		name:  "extra blank lines",
		index: "\n\nP:a\nV:1\n\n\n\nP:b\nV:2\n\n",
	}, {
		// ParsePackageIndex drops a stanza without a closing blank line.
		name:  "unterminated tail",
		index: "P:a\nV:1\n\nP:b\nV:2\n",
	}, {
		name:  "empty",
		index: "",
	}, {
		// ParsePackageIndex drops a stanza that names no package; its
		// record parses into nothing.
		name:    "nameless stanza",
		index:   "P:a\nV:1\n\nV:9\nT:no name\n\nP:b\nV:2\n\n",
		unnamed: 1,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			want, err := ParsePackageIndex(strings.NewReader(tc.index))
			require.NoError(t, err)

			got := []*Package{}
			unnamed := 0
			require.NoError(t, scanIndexRecords(strings.NewReader(tc.index), func(record []byte) error {
				require.True(t, bytes.HasSuffix(record, []byte("\n\n")), "record %q", record)
				pkgs, err := ParsePackageIndex(bytes.NewReader(record))
				require.NoError(t, err)
				if len(pkgs) == 0 {
					unnamed++
				}
				require.LessOrEqual(t, len(pkgs), 1)
				got = append(got, pkgs...)
				return nil
			}))
			require.Equal(t, want, got)
			require.Equal(t, tc.unnamed, unnamed)
		})
	}
}

func TestScanRepositoryIndexRejectsSecondIndexMember(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for _, body := range []string{"P:a\nV:1\n\n", "P:b\nV:2\n\n"} {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: apkIndexFilename, Mode: 0o644, Size: int64(len(body))}))
		_, err := tw.Write([]byte(body))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())

	// IndexFromArchive reads such an archive as its last member.
	index, err := IndexFromArchive(io.NopCloser(bytes.NewReader(buf.Bytes())))
	require.NoError(t, err)
	require.Len(t, index.Packages, 1)
	require.Equal(t, "b", index.Packages[0].Name)

	srv, _ := serveIndex(t, buf.Bytes(), "", "", "")
	_, _, err = scanAll(t, srv.URL, nil, WithHTTPClient(srv.Client()), WithIgnoreSignatures(true))
	require.ErrorContains(t, err, "more than one APKINDEX")
}

// TestScanRepositoryIndexBoundsSignatureSegment checks that the unsigned
// signature segment cannot make verification decompress without bound.
func TestScanRepositoryIndexBoundsSignatureSegment(t *testing.T) {
	key := newTestIndexKey(t)
	index := unsignedTestIndex(t, scanTestPackages(5))

	// segment prepends to index a signature segment whose one member is
	// size zero bytes, which compress to almost nothing.
	segment := func(name string, size int) []byte {
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gw)
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(size)}))
		_, err := tw.Write(make([]byte, size))
		require.NoError(t, err)
		require.NoError(t, tw.Flush())
		require.NoError(t, gw.Close())
		return append(buf.Bytes(), index...)
	}

	for _, tc := range []struct {
		name string
		body []byte
		opts []IndexOption
		want string
	}{{
		name: "oversized signature from a trusted key",
		body: segment(".SIGN.RSA256."+key.name, 1<<20),
		want: "more than the 65536 allowed",
	}, {
		name: "skipped signature past the decompressed limit",
		body: segment(".SIGN.RSA256.someone-else.rsa.pub", 1<<20),
		opts: []IndexOption{WithIndexDecompressedMaxSize(1 << 16)},
		want: "size limit exceeded",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := serveIndex(t, tc.body, "", "", "")
			calls := 0
			_, err := ScanRepositoryIndex(t.Context(), srv.URL, map[string][]byte{key.name: key.pub}, "x86_64", func([]byte) error {
				calls++
				return nil
			}, append(tc.opts, WithHTTPClient(srv.Client()))...)
			require.ErrorContains(t, err, tc.want)
			require.Zero(t, calls)
		})
	}
}
