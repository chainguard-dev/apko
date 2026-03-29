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

func TestParser(t *testing.T) {
	fsys := apkfs.NewMemFS()
	passwd, err := os.ReadFile("testdata/passwd")
	require.NoError(t, err)
	err = fsys.MkdirAll("etc", 0o755)
	require.NoError(t, err)
	err = fsys.WriteFile("etc/passwd", passwd, 0o600)
	require.NoError(t, err)
	uf, err := ReadOrCreateUserFile(fsys, "etc/passwd")
	require.NoError(t, err)
	require.NotEmpty(t, uf, "parsed passwd file should not be empty")

	found_root := false
	found_nobody := false
	for _, ue := range uf.Entries {
		if ue.UID == 0 {
			assert.Equal(t, "root", ue.UserName, "uid 0 is not root")
			assert.Equal(t, "/bin/ash", ue.Shell, "uid 0 shell is not /bin/ash")
			assert.Equal(t, "/root", ue.HomeDir, "uid 0 homedir is not /root")
			found_root = true
		}

		if ue.UID == 65534 {
			assert.Equal(t, "nobody", ue.UserName, "uid 65534 is not nobody")
			assert.Equal(t, "/bin/false", ue.Shell, "uid 65534 shell is not /bin/false")
			assert.Equal(t, "/", ue.HomeDir, "uid 65534 homedir is not /")
			found_nobody = true
		}
	}
	assert.True(t, found_root, "passwd file should contain the root user")
	assert.True(t, found_nobody, "passwd file should contain the nobody user")
}

func TestWriter(t *testing.T) {
	fsys := apkfs.NewMemFS()
	passwd, err := os.ReadFile("testdata/passwd")
	require.NoError(t, err)
	err = fsys.MkdirAll("etc", 0o755)
	require.NoError(t, err)
	err = fsys.WriteFile("etc/passwd", passwd, 0o600)
	require.NoError(t, err)
	uf, err := ReadOrCreateUserFile(fsys, "etc/passwd")
	require.NoError(t, err)

	w := &bytes.Buffer{}
	require.NoError(t, uf.Write(w))

	r := bytes.NewReader(w.Bytes())
	uf2 := &UserFile{}
	require.NoError(t, uf2.Load(r))

	w2 := &bytes.Buffer{}
	require.NoError(t, uf2.Write(w2))

	require.Equal(t, w.Bytes(), w2.Bytes())
}
