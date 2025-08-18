// Copyright 2024 Chainguard, Inc.
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

package build

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
)

func TestFetchFSReleaseData(t *testing.T) {
	osinfoData := `# This is a comment that should be ignored.
ID=wolfi
NAME="Wolfi"
PRETTY_NAME="Wolfi"
VERSION_ID="2022, 20230914"
HOME_URL="https://wolfi.dev"
`
	fsys := apkfs.NewMemFS()
	require.NoError(t, fsys.MkdirAll(filepath.Dir("/etc/os-release"), os.FileMode(0o644)))
	require.NoError(t, fsys.WriteFile("/etc/os-release", []byte(osinfoData), os.FileMode(0o644)))
	info, err := fetchFSReleaseData(fsys)
	require.NoError(t, err)
	require.Equal(t, "wolfi", info.ID, "id")
	require.Equal(t, "Wolfi", info.Name, "name")
	require.Equal(t, "2022, 20230914", info.VersionID, "version")
	require.Equal(t, "Wolfi", info.PrettyName, "pretty name")
}

func TestFetchFSReleaseData_EmptyDefaults(t *testing.T) {
	fsys := apkfs.NewMemFS()
	info, err := fetchFSReleaseData(fsys)
	require.NoError(t, err)
	require.Equal(t, "unknown", info.ID)
	require.Equal(t, "apko-generated image", info.Name)
	require.Equal(t, "unknown", info.VersionID)
	require.Equal(t, "", info.PrettyName)
}

func TestBadFSReleaseData(t *testing.T) {
	osinfoData := `hello, world! this is not a valid os-release file
`
	fsys := apkfs.NewMemFS()
	require.NoError(t, fsys.MkdirAll(filepath.Dir("/etc/os-release"), os.FileMode(0o644)))
	require.NoError(t, fsys.WriteFile("/etc/os-release", []byte(osinfoData), os.FileMode(0o644)))
	// Bad data in file should err.
	_, err := fetchFSReleaseData(fsys)
	require.Error(t, err)
}

func TestSbomPerms(t *testing.T) {
	ctx := context.Background()

	opts := []Option{
		WithConfig("apko.yaml", []string{"testdata"}),
	}

	bc, err := New(ctx, apkfs.NewMemFS(), opts...)
	if err != nil {
		t.Fatal(err)
	}

	require.NoError(t, bc.fs.MkdirAll("var/lib/db/sbom", 0o755))

	f, err := bc.fs.Create("var/lib/db/sbom/foo.spdx.json")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	err = bc.BuildImage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cache := "var/lib/db/sbom/foo.spdx.json"
	info, err := bc.fs.Stat(cache)
	if err != nil {
		t.Fatal(err)
	}
	mode := info.Mode()
	perm := mode.Perm()
	if perm != 0o644 {
		t.Errorf("%s has unexpected permissions: %v", cache, perm)
	}
}
