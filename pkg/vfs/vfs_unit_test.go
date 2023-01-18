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
	"golang.org/x/sys/unix"
)

func TestVFS(t *testing.T) {
	var (
		st1            *syscall.Stat_t
		st2            *unix.Stat_t
		ok1, ok2       bool
		uid, gid, mode uint32
	)
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

	sys := fi.Sys()
	st1, ok1 = sys.(*syscall.Stat_t)
	st2, ok2 = sys.(*unix.Stat_t)
	require.True(t, ok1 || ok2, "must present a Stat_t")
	if ok1 {
		uid = st1.Uid
	} else {
		uid = st2.Uid
	}
	assert.NotEqual(t, uid, uint32(65532), "Uid should not be 65532")

	err = vfs.Chown("./etc/motd", 65532, 65532)
	require.NoError(t, err)

	fi, err = vfs.Stat("./etc/motd")
	require.NoError(t, err)

	sys = fi.Sys()
	st1, ok1 = sys.(*syscall.Stat_t)
	st2, ok2 = sys.(*unix.Stat_t)
	require.True(t, ok1 || ok2, "must present a Stat_t")

	if ok1 {
		uid = st1.Uid
		gid = st1.Gid
	} else {
		uid = st2.Uid
		gid = st2.Gid
	}
	assert.Equal(t, uid, uint32(65532), "Uid must be 65532")
	assert.Equal(t, gid, uint32(65532), "Gid must be 65532")

	dentry, err = vfs.ReadDir("./etc")
	require.NoError(t, err)

	assert.Equal(t, len(dentry), 1, "etc/ should only have one child entry")
	assert.Equal(t, dentry[0].Name(), "motd", "That directory entry should be named motd")

	fi, err = dentry[0].Info()
	require.NoError(t, err)

	sys = fi.Sys()
	st1, ok1 = sys.(*syscall.Stat_t)
	st2, ok2 = sys.(*unix.Stat_t)
	require.True(t, ok1 || ok2, "must present a Stat_t")

	if ok1 {
		uid = st1.Uid
		gid = st1.Gid
	} else {
		uid = st2.Uid
		gid = st2.Gid
	}

	require.Equal(t, uid, uint32(65532), "Uid must be 65532")
	require.Equal(t, gid, uint32(65532), "Gid must be 65532")

	err = vfs.Chmod("./etc/motd", 0755)
	require.NoError(t, err)

	fi, err = vfs.Stat("./etc/motd")
	require.NoError(t, err)

	sys = fi.Sys()
	st1, ok1 = sys.(*syscall.Stat_t)
	st2, ok2 = sys.(*unix.Stat_t)
	require.True(t, ok1 || ok2, "must present a Stat_t")

	if ok1 {
		mode = uint32(st1.Mode) //nolint:unconvert // mode is uint32 on linux, uint16 on darwin
	} else {
		mode = uint32(st2.Mode) //nolint:unconvert // mode is uint32 on linux, uint16 on darwin
	}

	require.Equal(t, uint32(mode&0755), uint32(0755), "must have mode 0755") //nolint:unconvert // mode is uint32 on linux, uint16 on darwin
}
