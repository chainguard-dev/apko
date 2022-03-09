// Copyright 2022 Chainguard, Inc.
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

package sbom

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadReleaseData(t *testing.T) {
	osinfoData := `NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.15.0
PRETTY_NAME="Alpine Linux v3.15"
HOME_URL="https://alpinelinux.org/"
BUG_REPORT_URL="https://bugs.alpinelinux.org/"
`
	tdir := t.TempDir()
	require.NoError(
		t, os.WriteFile(
			filepath.Join(tdir, "os-release"), []byte(osinfoData), os.FileMode(0o644),
		),
	)
	di := defaultSBOMImplementation{}

	// Non existent file, should err
	require.Error(t, di.readReleaseData(&Options{}, filepath.Join(tdir, "non-existent")))
	opts := Options{}
	require.NoError(t, di.readReleaseData(&opts, filepath.Join(tdir, "os-release")))
	require.Equal(t, "alpine", opts.OsID)
	require.Equal(t, "Alpine Linux", opts.OsName)
	require.Equal(t, "3.15.0", opts.OsVersion)
}
