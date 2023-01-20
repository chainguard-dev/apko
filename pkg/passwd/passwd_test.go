// Copyright 2022, 2023 Chainguard, Inc.
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

	"github.com/stretchr/testify/require"

	apkfs "chainguard.dev/apko/pkg/apk/impl/fs"
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

	for _, ue := range uf.Entries {
		if ue.UID == 0 {
			require.Equal(t, "root", ue.UserName, "uid 0 is not root")
		}

		if ue.UID == 65534 {
			require.Equal(t, "nobody", ue.UserName, "uid 65534 is not nobody")
		}
	}
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
