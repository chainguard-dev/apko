// Copyright 2022-2026 Chainguard, Inc.
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

package passwd

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
)

func TestShadowParser(t *testing.T) {
	fsys := apkfs.NewMemFS()
	shadow, err := os.ReadFile("testdata/shadow")
	require.NoError(t, err)
	err = fsys.MkdirAll("etc", 0o755)
	require.NoError(t, err)
	err = fsys.WriteFile("etc/shadow", shadow, 0o640)
	require.NoError(t, err)
	sf, err := ReadOrCreateShadowFile(fsys, "etc/shadow")
	require.NoError(t, err)
	require.NotEmpty(t, sf, "parsed shadow file should not be empty")

	found_root := false
	found_bin := false
	for _, se := range sf.Entries {
		if se.UserName == "root" {
			// Alpine/wolfi convention: root is locked with "*", distinct
			// from the "!" used for other system accounts below.
			assert.Equal(t, "*", se.Password, "root password field should be *")
			assert.Equal(t, "", se.LastChg, "root last-changed field should be empty")
			assert.Equal(t, "0", se.Min, "root min field should be 0")
			found_root = true
		}

		if se.UserName == "bin" {
			assert.Equal(t, "!", se.Password, "bin password field should be locked (!)")
			assert.Equal(t, "", se.LastChg, "bin last-changed field should be empty")
			assert.Equal(t, "0", se.Min, "bin min field should be 0")
			assert.Equal(t, "", se.Max, "bin max field should be empty")
			found_bin = true
		}
	}
	assert.True(t, found_root, "shadow file should contain the root entry")
	assert.True(t, found_bin, "shadow file should contain the bin entry")
}

func TestShadowWriter(t *testing.T) {
	fsys := apkfs.NewMemFS()
	shadow, err := os.ReadFile("testdata/shadow")
	require.NoError(t, err)
	err = fsys.MkdirAll("etc", 0o755)
	require.NoError(t, err)
	err = fsys.WriteFile("etc/shadow", shadow, 0o640)
	require.NoError(t, err)
	sf, err := ReadOrCreateShadowFile(fsys, "etc/shadow")
	require.NoError(t, err)

	w := &bytes.Buffer{}
	require.NoError(t, sf.Write(w))

	r := bytes.NewReader(w.Bytes())
	sf2 := &ShadowFile{}
	require.NoError(t, sf2.Load(r))

	w2 := &bytes.Buffer{}
	require.NoError(t, sf2.Write(w2))

	require.Equal(t, w.Bytes(), w2.Bytes())

	// WriteFile enforces that, rather than as its own top-level test.
	require.NoError(t, sf.WriteFile("etc/shadow"))
	fi, err := fsys.Stat("etc/shadow")
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o640), fi.Mode().Perm(), "/etc/shadow should not be world-readable")
}
