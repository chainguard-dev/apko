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
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"time"

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/apko/pkg/apk/types"
	"chainguard.dev/apko/pkg/tarfs"
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
