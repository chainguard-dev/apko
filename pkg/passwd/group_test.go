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
	"testing"

	"github.com/stretchr/testify/require"

	apkfs "chainguard.dev/apko/pkg/apk/impl/fs"
)

func TestGroupParser(t *testing.T) {
	fsys := apkfs.DirFS("testdata")
	gf, err := ReadOrCreateGroupFile(fsys, "group")
	require.NoError(t, err)

	for _, ge := range gf.Entries {
		if ge.GID == 0 {
			require.Equal(t, "root", ge.GroupName, "gid 0 is not root")
		}

		if ge.GID == 65534 {
			require.Equal(t, "nobody", ge.GroupName, "gid 65534 is not nobody")
		}
	}
}

func TestGroupWriter(t *testing.T) {
	fsys := apkfs.DirFS("testdata")
	gf, err := ReadOrCreateGroupFile(fsys, "group")
	require.NoError(t, err)

	w := &bytes.Buffer{}
	require.NoError(t, gf.Write(w))

	r := bytes.NewReader(w.Bytes())
	gf2 := &GroupFile{}
	require.NoError(t, gf2.Load(r))

	w2 := &bytes.Buffer{}
	require.NoError(t, gf2.Write(w2))

	require.Equal(t, w.Bytes(), w2.Bytes())
}
