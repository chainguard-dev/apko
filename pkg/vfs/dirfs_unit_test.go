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

package vfs

import (
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDirFS(t *testing.T) {
	dir, err := DirFS("testdata")
	require.NoError(t, err)

	dentry, err := dir.ReadDir(".")
	require.NoError(t, err)

	assert.Equal(t, len(dentry), 1, "There should only be one directory entry")
	assert.Equal(t, dentry[0].Name(), "etc", "That directory entry should be named etc")

	dentry, err = dir.ReadDir("./etc")
	require.NoError(t, err)

	assert.Equal(t, len(dentry), 1, "etc/ should only have one child entry")
	assert.Equal(t, dentry[0].Name(), "motd", "That directory entry should be named motd")

	st, err := dir.Stat("./etc")
	require.NoError(t, err)

	assert.Equal(t, st.IsDir(), true, "etc/ is a directory")

	st, err = dir.Stat("./etc/motd")
	require.NoError(t, err)

	assert.Equal(t, st.IsDir(), false, "etc/motd is a normal file")

	inF, err := dir.Open("./etc/motd")
	require.NoError(t, err)
	defer inF.Close()

	data, err := io.ReadAll(inF)
	require.NoError(t, err)

	assert.Equal(t, data, []byte("Hello world\n"), "motd should return Hello world")

	otherdata, err := dir.ReadFile("./etc/motd")
	require.NoError(t, err)
	assert.Equal(t, data, otherdata, "dir.ReadFile behavior should match os.ReadFile")

	outF, err := dir.Create("./etc/motd2")
	require.NoError(t, err)
	defer outF.Close()
	defer dir.Remove("./etc/motd2")

	_, err = outF.Write(data)
	require.NoError(t, err)

	moredata, err := dir.ReadFile("./etc/motd2")
	require.NoError(t, err)
	assert.Equal(t, data, moredata, "motd2 should match motd")
}
