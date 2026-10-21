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

package tarfs_test

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"io/fs"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/apk/expandapk/tarfs"
	"chainguard.dev/apko/pkg/cas"
)

func TestEntriesCarryDigests(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	files := map[string]string{
		"usr/bin/a": "alpha",
		"usr/bin/b": "bravo",
		"usr/bin/c": "alpha",
		"usr/bin/d": "",
		"usr/bin/e": strings.Repeat("x", 70*1024),
	}
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "usr/bin", Typeflag: tar.TypeDir, Mode: 0o755}))
	for _, name := range []string{"usr/bin/a", "usr/bin/b", "usr/bin/c", "usr/bin/d", "usr/bin/e"} {
		data := files[name]
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(data))}))
		_, err := tw.Write([]byte(data))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())

	src := &countedReaderAt{ReaderAt: bytes.NewReader(buf.Bytes())}
	fsys, err := tarfs.New(src, int64(buf.Len()))
	require.NoError(t, err)

	for _, e := range fsys.Entries() {
		if e.Header.Typeflag != tar.TypeReg {
			continue
		}
		want := files[e.Header.Name]
		require.Equal(t, cas.Of([]byte(want)), e.Digest, e.Header.Name)
		reads := src.reads
		digest, err := fsys.Digest(e.Header.Name)
		require.NoError(t, err)
		require.Equal(t, e.Digest, digest)
		require.Equal(t, reads, src.reads)

		r, err := fsys.OpenBlob(e.Digest)
		require.NoError(t, err)
		got, err := io.ReadAll(r)
		require.NoError(t, err)
		require.Equal(t, want, string(got), e.Header.Name)
	}

	_, err = fsys.OpenBlob(cas.Of([]byte("not in the archive")))
	require.ErrorIs(t, err, cas.ErrNotFound)
	_, err = fsys.Digest("missing")
	require.ErrorIs(t, err, fs.ErrNotExist)
	_, err = fsys.Digest("usr/bin")
	require.ErrorIs(t, err, fs.ErrInvalid)
}

func TestDigestDuplicateNames(t *testing.T) {
	for _, lastType := range []byte{tar.TypeReg, tar.TypeSymlink} {
		t.Run(string(lastType), func(t *testing.T) {
			var buf bytes.Buffer
			tw := tar.NewWriter(&buf)
			contents := []string{"hello", "world!"}
			for _, content := range contents {
				require.NoError(t, tw.WriteHeader(&tar.Header{Name: "file", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(content))}))
				_, err := io.WriteString(tw, content)
				require.NoError(t, err)
			}
			require.NoError(t, tw.WriteHeader(&tar.Header{Name: "file", Typeflag: lastType, Linkname: "target"}))
			require.NoError(t, tw.Close())
			src := &countedReaderAt{ReaderAt: bytes.NewReader(buf.Bytes())}
			fsys, err := tarfs.New(src, int64(buf.Len()))
			require.NoError(t, err)
			reads := src.reads
			_, err = fsys.Digest("file")
			require.ErrorIs(t, err, errors.ErrUnsupported)
			require.Equal(t, reads, src.reads)
			for i, content := range contents {
				entry := fsys.Entries()[i]
				require.Equal(t, cas.Of([]byte(content)), entry.Digest)
				r, err := fsys.OpenBlob(entry.Digest)
				require.NoError(t, err)
				got, err := io.ReadAll(r)
				require.NoError(t, err)
				require.Equal(t, content, string(got))
			}
		})
	}
}

type countedReaderAt struct {
	io.ReaderAt
	reads int
}

func (r *countedReaderAt) ReadAt(p []byte, off int64) (int, error) {
	r.reads++
	return r.ReaderAt.ReadAt(p, off)
}

func BenchmarkNewEmptyFiles(b *testing.B) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for i := range 10000 {
		require.NoError(b, tw.WriteHeader(&tar.Header{
			Name:     strconv.Itoa(i),
			Typeflag: tar.TypeReg,
			Mode:     0o644,
		}))
	}
	require.NoError(b, tw.Close())

	b.ReportAllocs()
	for b.Loop() {
		_, err := tarfs.New(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
		require.NoError(b, err)
	}
}
