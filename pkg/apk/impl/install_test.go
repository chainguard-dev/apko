// Copyright 2023 Chainguard, Inc.
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

package impl

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io/fs"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInstallAPKFiles(t *testing.T) {
	apk, src, err := testGetTestAPK()
	require.NoErrorf(t, err, "failed to get test APK")

	var finalDoubleWriteContent = []byte("second write is much longer")

	// create a tgz stream with our files
	dirs := []struct {
		name  string
		perms os.FileMode
	}{
		{"etc", os.ModeDir | 0755},
		{"etc/foo", os.ModeDir | 0755},
		{"var", os.ModeDir | 0755},
		{"var/lib", os.ModeDir | 0755},
		{"var/lib/test", os.ModeDir | 0755},
	}
	files := []struct {
		name        string
		overwritten bool // whether or not this file is expected to be overwritten, so ignore it in a check
		perms       os.FileMode
		content     []byte
	}{
		{"etc/foo/bar", false, 0644, []byte("hello world")},
		{"var/lib/test/foobar", false, 0644, []byte("hello var/lib")},
		{"etc/doublewrite", true, 0644, []byte("first")},
		{"etc/doublewrite", false, 0644, finalDoubleWriteContent},
	}
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	// write the dirs before the files, to ensure the dirs exist by the time the files are written
	for _, d := range dirs {
		tw.WriteHeader(&tar.Header{
			Name:     d.name,
			Typeflag: tar.TypeDir,
			Mode:     int64(d.perms),
		})
	}
	for _, f := range files {
		tw.WriteHeader(&tar.Header{
			Name:     f.name,
			Typeflag: tar.TypeReg,
			Mode:     int64(f.perms),
			Size:     int64(len(f.content)),
		})
		tw.Write(f.content)
	}
	tw.Close()
	gw.Close()
	// create the reader
	r := bytes.NewReader(buf.Bytes())
	headers, err := apk.installAPKFiles(r)
	require.NoError(t, err)

	require.Equal(t, len(headers), len(dirs)+len(files))

	// compare each one to make sure it is in the returned list
	headerMap := map[string]tar.Header{}
	for _, h := range headers {
		headerMap[h.Name] = h
	}
	for _, d := range dirs {
		h, ok := headerMap[d.name]
		require.True(t, ok, "directory %s not found in headers", d.name)
		require.Equal(t, tar.TypeDir, rune(h.Typeflag), "mismatched file type for %s", d.name)
		require.Equal(t, int64(d.perms), h.Mode, "mismatched permissions for %s", d.name)
		delete(headerMap, d.name)
	}
	for _, f := range files {
		if f.overwritten {
			continue
		}
		h, ok := headerMap[f.name]
		require.True(t, ok, "file %s not found in headers", f.name)
		require.Equal(t, tar.TypeReg, rune(h.Typeflag), "mismatched file type for %s", f.name)
		require.Equal(t, h.Mode, int64(f.perms), "mismatched permissions for %s", f.name)
		require.Equal(t, int64(len(f.content)), h.Size, "mismatched size for %s", f.name)
		delete(headerMap, f.name)
	}

	// compare each one in the memfs filesystem to make sure it was installed correctly
	for _, d := range dirs {
		fi, err := fs.Stat(src, d.name)
		require.NoError(t, err, "error statting %s", d.name)
		require.True(t, fi.IsDir(), "expected %s to be a directory, got %v", d.name, fi.Mode())
		require.Equal(t, fi.Mode(), d.perms, "expected %s to have permissions %v, got %v", d.name, d.perms, fi.Mode())
	}
	for _, f := range files {
		if f.overwritten {
			continue
		}
		fi, err := fs.Stat(src, f.name)
		require.NoError(t, err, "error statting %s", f.name)
		require.True(t, fi.Mode().IsRegular(), "expected %s to be a regular file, got %v", f.name, fi.Mode())
		require.Equal(t, fi.Mode(), f.perms, "expected %s to have permissions %v, got %v", f.name, f.perms, fi.Mode())
		require.Equal(t, fi.Size(), int64(len(f.content)), "expected %s to have size %d, got %d", f.name, len(f.content), fi.Size())
		actual, err := src.ReadFile(f.name)
		require.NoError(t, err, "error reading %s", f.name)
		require.True(t, bytes.Equal(actual, f.content), "unexpected content for %s: expected %q, got %q", f.name, f.content, actual)
	}
}
