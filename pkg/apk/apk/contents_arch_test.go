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

package apk_test

import (
	"archive/tar"
	"bytes"
	"crypto/sha1" //nolint:gosec // APK file checksums use SHA-1.
	"fmt"
	"io"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"chainguard.dev/apko/pkg/apk/apk"
	archivetarfs "chainguard.dev/apko/pkg/apk/expandapk/tarfs"
	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/apk/types"
	"chainguard.dev/apko/pkg/tarfs"
	"github.com/stretchr/testify/require"
)

// stubContents is the minimal PackageContents the arch guard needs: package
// metadata and no files at all.
type stubContents struct {
	info *types.PackageInfo
}

func (s stubContents) PkgInfo() (*types.PackageInfo, error) { return s.info, nil }
func (s stubContents) ControlSection() ([]byte, error)      { return []byte("control"), nil }
func (s stubContents) ControlData() ([]byte, error)         { return nil, nil }
func (s stubContents) Size() int64                          { return 42 }
func (s stubContents) Entries() ([]tar.Header, error)       { return nil, nil }
func (s stubContents) FS() fs.FS                            { return nil }

type fileContents struct {
	stubContents
	entries []tar.Header
	source  fs.FS
}

func (c fileContents) Entries() ([]tar.Header, error) { return c.entries, nil }
func (c fileContents) FS() fs.FS                      { return c.source }

type headerWriterFS struct {
	apkfs.FullFS
	writer  apk.WriteHeaderer
	headers []tar.Header
	source  fs.FS
}

func (f *headerWriterFS) WriteHeader(hdr tar.Header, src fs.FS, pkg *apk.Package) (bool, error) {
	f.headers = append(f.headers, hdr)
	f.source = src
	return f.writer.WriteHeader(hdr, src, pkg)
}

type countingFS struct {
	fs.FS
	opens int
}

func (f *countingFS) Open(name string) (fs.File, error) {
	f.opens++
	return f.FS.Open(name)
}

func TestInstallPackageContentsWriteHeader(t *testing.T) {
	for _, indexed := range []bool{false, true} {
		t.Run(fmt.Sprint(indexed), func(t *testing.T) {
			hdr := tar.Header{
				Name: "file", Typeflag: tar.TypeReg, Mode: 0o644, Size: 5,
				PAXRecords: map[string]string{"APK-TOOLS.checksum.SHA1": fmt.Sprintf("%x", sha1.Sum([]byte("hello")))}, //nolint:gosec // APK file checksums use SHA-1.
			}
			legacy := &countingFS{FS: fstest.MapFS{"file": &fstest.MapFile{Data: []byte("hello")}}}
			var src fs.FS = legacy
			if indexed {
				var buf bytes.Buffer
				tw := tar.NewWriter(&buf)
				require.NoError(t, tw.WriteHeader(&hdr))
				_, err := io.WriteString(tw, "hello")
				require.NoError(t, err)
				require.NoError(t, tw.Close())
				src, err = archivetarfs.New(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
				require.NoError(t, err)
			}
			inner := tarfs.New()
			wrapped := &headerWriterFS{FullFS: inner, writer: inner}
			a, err := apk.New(t.Context(), apk.WithFS(wrapped), apk.WithArch("aarch64"), apk.WithIgnoreMknodErrors(true))
			require.NoError(t, err)
			require.NoError(t, a.InitDB(t.Context()))
			contents := fileContents{
				stubContents: stubContents{info: &types.PackageInfo{Name: "example", Version: "1.0", Arch: "noarch"}},
				entries:      []tar.Header{hdr},
				source:       src,
			}
			epoch := time.Time{}
			_, err = a.InstallPackageContents(t.Context(), &epoch, []apk.PackageContents{contents})
			require.NoError(t, err)
			require.Equal(t, []tar.Header{hdr}, wrapped.headers)
			require.Same(t, src, wrapped.source)
			require.Zero(t, legacy.opens)
			got, err := inner.ReadFile("file")
			require.NoError(t, err)
			require.Equal(t, "hello", string(got))
			if !indexed {
				require.Equal(t, 1, legacy.opens)
			}
		})
	}
}

// TestInstallPackageContentsArch: one option set serves every architecture of
// a multi-arch build, so contents for the wrong architecture can arrive at any
// context — they must be refused, while matching, noarch, and unstated
// architectures install.
func TestInstallPackageContentsArch(t *testing.T) {
	ctx := t.Context()
	epoch := time.Time{}

	a, err := apk.New(ctx, apk.WithFS(tarfs.New()), apk.WithArch("aarch64"), apk.WithIgnoreMknodErrors(true))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.InitDB(ctx); err != nil {
		t.Fatal(err)
	}

	_, err = a.InstallPackageContents(ctx, &epoch, []apk.PackageContents{stubContents{
		info: &types.PackageInfo{Name: "foreign", Version: "1.0.0", Arch: "x86_64"},
	}})
	if err == nil {
		t.Fatal("foreign-arch install: got = nil, wanted an error")
	}
	for _, want := range []string{"x86_64", "aarch64"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("foreign-arch error %q: wanted it to name %q", err, want)
		}
	}

	for i, arch := range []string{"aarch64", "noarch", ""} {
		diffs, err := a.InstallPackageContents(ctx, &epoch, []apk.PackageContents{stubContents{
			info: &types.PackageInfo{Name: fmt.Sprintf("native-%d", i), Version: "1.0.0", Arch: arch},
		}})
		if err != nil {
			t.Fatalf("arch %q install: %v", arch, err)
		}
		if len(diffs) != 1 {
			t.Errorf("arch %q diffs: got = %d, wanted = 1", arch, len(diffs))
		}
	}
}
