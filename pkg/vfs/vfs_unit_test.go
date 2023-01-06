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
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVFS(t *testing.T) {
	dir, err := DirFS("testdata")
	require.NoError(t, err)

	vfs, err := New(dir)
	require.NoError(t, err)

	dentry, err := vfs.ReadDir(".")
	require.NoError(t, err)

	assert.Equal(t, len(dentry), 1, "There should only be one directory entry")
	assert.Equal(t, dentry[0].Name(), "etc", "That directory entry should be named etc")

	dentry, err = vfs.ReadDir("./etc")
	require.NoError(t, err)

	assert.Equal(t, len(dentry), 1, "etc/ should only have one child entry")
	assert.Equal(t, dentry[0].Name(), "motd", "That directory entry should be named motd")

	fi, err := vfs.Stat("./etc/motd")
	require.NoError(t, err)

	st, ok := fi.Sys().(*syscall.Stat_t)
	require.True(t, ok, "must present a Stat_t")

	assert.NotEqual(t, st.Uid, uint32(65532), "Uid should not be 65532")

	err = vfs.Chown("./etc/motd", 65532, 65532)
	require.NoError(t, err)

	fi, err = vfs.Stat("./etc/motd")
	require.NoError(t, err)

	st, ok = fi.Sys().(*syscall.Stat_t)
	require.True(t, ok, "must present a Stat_t")

	assert.Equal(t, st.Uid, uint32(65532), "Uid must be 65532")
	assert.Equal(t, st.Gid, uint32(65532), "Gid must be 65532")

	dentry, err = vfs.ReadDir("./etc")
	require.NoError(t, err)

	assert.Equal(t, len(dentry), 1, "etc/ should only have one child entry")
	assert.Equal(t, dentry[0].Name(), "motd", "That directory entry should be named motd")

	fi, err = dentry[0].Info()
	require.NoError(t, err)

	st, ok = fi.Sys().(*syscall.Stat_t)
	require.True(t, ok, "must present a Stat_t")

	require.Equal(t, st.Uid, uint32(65532), "Uid must be 65532")
	require.Equal(t, st.Gid, uint32(65532), "Gid must be 65532")

	err = vfs.Chmod("./etc/motd", 0755)
	require.NoError(t, err)

	fi, err = vfs.Stat("./etc/motd")
	require.NoError(t, err)

	st, ok = fi.Sys().(*syscall.Stat_t)
	require.True(t, ok, "must present a Stat_t")

	require.Equal(t, st.Mode&0755, uint32(0755), "must have mode 0755")
}
