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

package tarfs_test

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // APK file checksums use SHA-1.
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/apk/apk"
	archivetarfs "chainguard.dev/apko/pkg/apk/expandapk/tarfs"

	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/cas"
	"chainguard.dev/apko/pkg/tarfs"
)

func TestTarFS(t *testing.T) {
	tfs := tarfs.New()
	ctx := context.Background()

	opts := []build.Option{
		// Keep the disk cache and scratch files out of the user's cache
		// directory and $TMPDIR.
		build.WithCache(t.TempDir(), false, apk.NewCache(false)),
		build.WithTempDir(t.TempDir()),
		build.WithConfig(filepath.Join("testdata", "apko.yaml"), []string{}),
	}

	bc, err := build.New(ctx, tfs, opts...)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := bc.BuildLayer(ctx); err != nil {
		t.Fatal(err)
	}

	installed, err := bc.InstalledPackages()
	if err != nil {
		t.Fatal(err)
	}

	// Check that everything in installed was written.
	for _, pkg := range installed {
		for _, hdr := range pkg.Files {
			// It should exist at least.
			stat, err := tfs.Stat(hdr.Name)
			if err != nil {
				t.Errorf("stat file %q: %v", hdr.Name, err)
				continue
			}

			if stat.Size() == 0 {
				continue
			}

			if _, err := tfs.Open(hdr.Name); err != nil {
				t.Errorf("opening %q: %v", hdr.Name, err)
			}
		}
	}

	// Pull a file out of the apk that we know exists and hit a bunch of edge cases.
	pkg := installed[1]
	want := "etc/os-release"
	var file *tar.Header
	for _, hdr := range pkg.Files {
		if hdr.Name == want {
			file = &hdr
			break
		}
	}
	if file == nil {
		t.Fatalf("did not find %q", want)
		return
	}
	file.Typeflag = tar.TypeReg

	contents, err := tfs.ReadFile(file.Name)
	if err != nil {
		t.Fatal(err)
	}
	blobs := cas.NewMemory()
	same := apk.Entry{Header: *file, Digest: blobs.Put(contents)}
	replacement := []byte("something else")
	different := apk.Entry{Header: *file, Digest: blobs.Put(replacement)}
	different.Header.Size = int64(len(replacement))

	otherPkg := &apk.Package{Origin: "different", Name: "different"}

	if _, err := tfs.WriteEntry(same, blobs, otherPkg); err != nil {
		t.Errorf("matching digest should be skipped, got %v", err)
	}

	if _, err := tfs.WriteEntry(different, blobs, otherPkg); err == nil {
		t.Errorf("wanted conflicting digest err, got nil")
	}

	otherPkg.Replaces = []string{pkg.Name}
	if _, err := tfs.WriteEntry(different, blobs, otherPkg); err != nil {
		t.Errorf("pkg replaces file, got %v", err)
	}
	got, err := tfs.ReadFile(file.Name)
	require.NoError(t, err)
	require.Equal(t, replacement, got)

	// Ensure that symlinks work with replaces.
	{
		original := tar.Header{
			Name:     "etc/os-release-symlink",
			Typeflag: tar.TypeSymlink,
			Linkname: "etc/os-release-symlink",
		}
		if _, err := tfs.WriteEntry(apk.Entry{Header: original}, blobs, &pkg.Package); err != nil {
			t.Fatalf("symlinking: %v", err)
		}

		link := tar.Header{
			Name:     "etc/os-release-symlink",
			Typeflag: tar.TypeSymlink,
			Linkname: "etc/somewhere-else",
		}
		if _, err := tfs.WriteEntry(apk.Entry{Header: link}, blobs, otherPkg); err != nil {
			t.Errorf("pkg replaces symlink, got %v", err)
		}

		target, err := tfs.Readlink(link.Name)
		if err != nil {
			t.Fatal(err)
		}

		if want, got := "etc/somewhere-else", target; want != got {
			t.Errorf("readlink: want %q, got %q", want, got)
		}
	}
}

func TestTarFSCreate(t *testing.T) {
	var (
		tfs = tarfs.New()
		err error
	)
	fd, err := tfs.Create("testfile")
	require.NoError(t, err)

	fileInfo, err := fd.Stat()
	require.NoError(t, err)
	require.Equal(t, fileInfo.Mode(), fs.FileMode(0o644))
}

func TestOpenHandles(t *testing.T) {
	for _, name := range []string{"written", "packaged", "legacy"} {
		t.Run(name, func(t *testing.T) {
			tfs := tarfs.New()
			if name == "packaged" {
				blobs := cas.NewMemory()
				_, err := tfs.WriteEntry(apk.Entry{
					Header: tar.Header{Name: "file", Typeflag: tar.TypeReg, Mode: 0o644, Size: 5},
					Digest: blobs.Put([]byte("hello")),
				}, blobs, nil)
				require.NoError(t, err)
			} else if name == "legacy" {
				hdr, src := packageSource(t, "hello", false, true)
				tracked := &countedFS{FS: src}
				t.Cleanup(func() { require.Equal(t, tracked.opens, tracked.closes) })
				_, err := tfs.WriteHeader(hdr, tracked, nil)
				require.NoError(t, err)
			} else {
				require.NoError(t, tfs.WriteFile("file", []byte("hello"), 0o644))
			}

			r, err := tfs.OpenReaderAt("file")
			require.NoError(t, err)
			defer r.Close()
			prefix := make([]byte, 2)
			_, err = io.ReadFull(r, prefix)
			require.NoError(t, err)
			require.Equal(t, "he", string(prefix))

			w, err := tfs.OpenFile("file", os.O_RDWR, 0)
			require.NoError(t, err)
			defer w.Close()
			other, err := tfs.OpenFile("file", os.O_RDWR, 0)
			require.NoError(t, err)
			require.NoError(t, other.Close())
			got, err := io.ReadAll(w)
			require.NoError(t, err)
			require.Equal(t, "hello", string(got))

			_, err = w.Seek(0, io.SeekStart)
			require.NoError(t, err)
			_, err = w.Write([]byte("world!"))
			require.NoError(t, err)
			got, err = io.ReadAll(r)
			require.NoError(t, err)
			require.Equal(t, "rld!", string(got))
			got = make([]byte, 6)
			n, err := r.ReadAt(got, 0)
			require.NoError(t, err)
			require.Equal(t, 6, n)
			require.Equal(t, "world!", string(got))
			n, err = r.ReadAt(got, 4)
			require.ErrorIs(t, err, io.EOF)
			require.Equal(t, 2, n)
			end, err := r.Seek(0, io.SeekEnd)
			require.NoError(t, err)
			require.EqualValues(t, 6, end)
			_, err = r.Seek(-1, io.SeekStart)
			require.Error(t, err)
			_, err = r.Write([]byte("not writable"))
			require.Error(t, err)

			require.NoError(t, tfs.WriteFile("file", []byte("short"), 0o644))
			_, err = r.Seek(0, io.SeekStart)
			require.NoError(t, err)
			got, err = io.ReadAll(r)
			require.NoError(t, err)
			require.Equal(t, "short", string(got))
		})
	}
}

type countedFS struct {
	fs.FS
	opens  int
	closes int
}

func (f *countedFS) Open(name string) (fs.File, error) {
	f.opens++
	r, err := f.FS.Open(name)
	if err != nil {
		return nil, err
	}
	return countedFile{File: r, owner: f}, nil
}

type countedFile struct {
	fs.File
	owner *countedFS
}

func (f countedFile) Close() error {
	f.owner.closes++
	return f.File.Close()
}

func packageSource(t *testing.T, content string, digest, checksum bool) (tar.Header, fs.FS) {
	t.Helper()
	hdr := tar.Header{Name: "file", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(content))}
	if checksum {
		hdr.PAXRecords = map[string]string{"APK-TOOLS.checksum.SHA1": fmt.Sprintf("%x", sha1.Sum([]byte(content)))} //nolint:gosec // APK file checksums use SHA-1.
	}
	if !digest {
		return hdr, fstest.MapFS{"file": &fstest.MapFile{Data: []byte(content), Mode: 0o644}}
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	require.NoError(t, tw.WriteHeader(&hdr))
	_, err := io.WriteString(tw, content)
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	src, err := archivetarfs.New(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	require.NoError(t, err)
	return hdr, src
}

func TestWriteHeaderContents(t *testing.T) {
	for _, firstDigest := range []bool{false, true} {
		for _, secondDigest := range []bool{false, true} {
			for _, modified := range []bool{false, true} {
				t.Run(fmt.Sprintf("digest=%t/%t/modified=%t", firstDigest, secondDigest, modified), func(t *testing.T) {
					tfs := tarfs.New()
					first := &apk.Package{Name: "first", Origin: "first"}
					second := &apk.Package{Name: "second", Origin: "second"}
					hdr, src := packageSource(t, "hello", firstDigest, true)
					var legacy []*countedFS
					if !firstDigest {
						f := &countedFS{FS: src}
						legacy = append(legacy, f)
						src = f
					}
					installed, err := tfs.WriteHeader(hdr, src, first)
					require.NoError(t, err)
					require.True(t, installed)
					content := "hello"
					if modified {
						content = "world"
						require.NoError(t, tfs.WriteFile("file", []byte(content), 0o644))
					}
					hdr, src = packageSource(t, content, secondDigest, true)
					if !secondDigest {
						f := &countedFS{FS: src}
						legacy = append(legacy, f)
						src = f
					}
					installed, err = tfs.WriteHeader(hdr, src, second)
					require.NoError(t, err)
					require.False(t, installed)
					for _, f := range legacy {
						require.Zero(t, f.opens, "installation and checksum comparisons must not open legacy content")
					}
					hdr, src = packageSource(t, "different", secondDigest, true)
					_, err = tfs.WriteHeader(hdr, src, second)
					var conflict apk.FileConflictError
					require.ErrorAs(t, err, &conflict)
					got, err := tfs.ReadFile("file")
					require.NoError(t, err)
					require.Equal(t, content, string(got))
					second.Replaces = []string{first.Name}
					installed, err = tfs.WriteHeader(hdr, src, second)
					require.NoError(t, err)
					require.True(t, installed)
					got, err = tfs.ReadFile("file")
					require.NoError(t, err)
					require.Equal(t, "different", string(got))
					for _, f := range legacy {
						require.Equal(t, f.opens, f.closes)
					}
				})
			}
		}
	}
}

func TestWriteHeaderMixedChecksums(t *testing.T) {
	for _, legacyFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(legacyFirst), func(t *testing.T) {
			tfs := tarfs.New()
			hdr, src := packageSource(t, "hello", false, true)
			legacy := &countedFS{FS: src}
			digestHeader, digestSource := packageSource(t, "hello", true, false)
			if legacyFirst {
				_, err := tfs.WriteHeader(hdr, legacy, nil)
				require.NoError(t, err)
				installed, err := tfs.WriteHeader(digestHeader, digestSource, nil)
				require.NoError(t, err)
				require.False(t, installed)
			} else {
				_, err := tfs.WriteHeader(digestHeader, digestSource, nil)
				require.NoError(t, err)
				installed, err := tfs.WriteHeader(hdr, legacy, nil)
				require.NoError(t, err)
				require.False(t, installed)
			}
			require.Equal(t, 1, legacy.opens)
			require.Equal(t, legacy.opens, legacy.closes)
		})
	}
}

func TestWriteHeaderDuplicateNames(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for i, content := range []string{"hello", "world!"} {
		hdr, _ := packageSource(t, content, false, true)
		if i == 1 {
			hdr.Mode = 0o755
		}
		require.NoError(t, tw.WriteHeader(&hdr))
		_, err := io.WriteString(tw, content)
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	src, err := archivetarfs.New(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	require.NoError(t, err)

	tfs := tarfs.New()
	pkg := &apk.Package{Name: "example", Origin: "example"}
	for _, entry := range src.Entries() {
		installed, err := tfs.WriteHeader(entry.Header, src, pkg)
		require.NoError(t, err)
		require.True(t, installed)
	}
	info, err := tfs.Stat("file")
	require.NoError(t, err)
	require.Equal(t, int64(6), info.Size())
	require.Equal(t, fs.FileMode(0o755), info.Mode().Perm())
	got, err := tfs.ReadFile("file")
	require.NoError(t, err)
	require.Equal(t, "world!", string(got))
}

func TestWriteEntryDoesNotRetainUnusedStore(t *testing.T) {
	for _, outcome := range []string{"missing parent", "conflict", "identical", "replaced"} {
		t.Run(outcome, func(t *testing.T) {
			tfs := tarfs.New()
			hdr, source := packageSource(t, "hello", true, true)
			archive := source.(*archivetarfs.FS)
			f, err := os.CreateTemp(t.TempDir(), "archive")
			require.NoError(t, err)
			t.Cleanup(func() { f.Close() })
			_, err = io.Copy(f, io.NewSectionReader(archive.UnderlyingReader(), 0, archive.Size()))
			require.NoError(t, err)
			src, err := archivetarfs.New(f, archive.Size())
			require.NoError(t, err)
			entry := apk.Entry{Header: hdr, Digest: cas.Of([]byte("hello"))}
			pkg := &apk.Package{Name: "incoming", Origin: "incoming"}
			switch outcome {
			case "missing parent":
				entry.Header.Name = "missing/file"
			case "conflict":
				require.NoError(t, tfs.WriteFile("file", []byte("keep"), 0o644))
			case "identical":
				require.NoError(t, tfs.WriteFile("file", []byte("hello"), 0o644))
			case "replaced":
				previous := &apk.Package{Name: "existing", Origin: "existing", Replaces: []string{pkg.Name}}
				hdr, legacy := packageSource(t, "keep", false, true)
				_, err := tfs.WriteHeader(hdr, legacy, previous)
				require.NoError(t, err)
			}
			installed, err := tfs.WriteEntry(entry, src, pkg)
			if outcome == "missing parent" || outcome == "conflict" {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.False(t, installed)
			require.NoError(t, src.Close())

			entry.Header.Name = "other"
			installed, err = tfs.WriteEntry(entry, archive, pkg)
			require.NoError(t, err)
			require.True(t, installed)
			got, err := tfs.ReadFile("other")
			require.NoError(t, err)
			require.Equal(t, "hello", string(got))
		})
	}
}

func TestWriteEntryRejectsIncompleteContents(t *testing.T) {
	for _, missing := range []string{"digest", "store"} {
		t.Run(missing, func(t *testing.T) {
			tfs := tarfs.New()
			blobs := cas.NewMemory()
			entry := apk.Entry{
				Header: tar.Header{Name: "file", Typeflag: tar.TypeReg, Mode: 0o644, Size: 5},
				Digest: blobs.Put([]byte("hello")),
			}
			var store cas.Store = blobs
			if missing == "digest" {
				entry.Digest = cas.Digest{}
			} else {
				store = nil
			}
			installed, err := tfs.WriteEntry(entry, store, nil)
			require.Error(t, err)
			require.False(t, installed)
			_, err = tfs.Stat("file")
			require.ErrorIs(t, err, fs.ErrNotExist)

			require.NoError(t, tfs.WriteFile("file", []byte("keep"), 0o644))
			installed, err = tfs.WriteEntry(entry, store, nil)
			require.Error(t, err)
			require.False(t, installed)
			got, err := tfs.ReadFile("file")
			require.NoError(t, err)
			require.Equal(t, "keep", string(got))
		})
	}
}

func TestWriteEntryMatchesWrittenContents(t *testing.T) {
	tfs := tarfs.New()
	f, err := tfs.Create("file")
	require.NoError(t, err)
	defer f.Close()
	blobs := cas.NewMemory()
	var contents []byte
	for _, part := range []string{"hello", " world"} {
		_, err := f.Write([]byte(part))
		require.NoError(t, err)
		contents = append(contents, part...)
		installed, err := tfs.WriteEntry(apk.Entry{
			Header: tar.Header{Name: "file", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(contents))},
			Digest: blobs.Put(append([]byte(nil), contents...)),
		}, blobs, nil)
		require.NoError(t, err)
		require.False(t, installed)
		got, err := tfs.ReadFile("file")
		require.NoError(t, err)
		require.Equal(t, contents, got)
	}
}

func TestWriteHeaderRejectsIncompleteContents(t *testing.T) {
	for _, invalid := range []string{"source", "checksum", "malformed checksum", "missing indexed entry"} {
		t.Run(invalid, func(t *testing.T) {
			hdr, src := packageSource(t, "hello", invalid == "missing indexed entry", true)
			switch invalid {
			case "source":
				src = nil
			case "checksum":
				hdr.PAXRecords = nil
			case "malformed checksum":
				hdr.PAXRecords["APK-TOOLS.checksum.SHA1"] = "invalid"
			case "missing indexed entry":
				hdr.Name = "missing"
			}
			tfs := tarfs.New()
			installed, err := tfs.WriteHeader(hdr, src, nil)
			require.Error(t, err)
			require.False(t, installed)
			_, err = tfs.Stat(hdr.Name)
			require.ErrorIs(t, err, fs.ErrNotExist)
			require.NoError(t, tfs.WriteFile(hdr.Name, []byte("keep"), 0o644))
			installed, err = tfs.WriteHeader(hdr, src, nil)
			require.Error(t, err)
			require.False(t, installed)
			got, err := tfs.ReadFile(hdr.Name)
			require.NoError(t, err)
			require.Equal(t, "keep", string(got))
		})
	}
}
