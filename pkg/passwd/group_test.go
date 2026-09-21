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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
)

func TestGroupParser(t *testing.T) {
	fsys := apkfs.DirFS(t.Context(), "testdata")
	gf, err := ReadOrCreateGroupFile(fsys, "group")
	require.NoError(t, err)

	require.NotEmpty(t, gf, "group file in existing testdata file should not be empty")

	found_root := false
	found_daemon := false
	found_nobody := false
	for _, ge := range gf.Entries {
		if ge.GID == 0 {
			assert.Equal(t, "root", ge.GroupName, "gid 0 is not root")
			assert.Equal(t, "x", ge.Password, "gid 0 password entry is not set to x")
			assert.Equal(t, []string{"root"}, ge.Members, "gid 0 members should just be the root user")
			found_root = true
		}

		if ge.GID == 2 {
			assert.Equal(t, "daemon", ge.GroupName, "gid 2 is not daemon")
			assert.Equal(t, "x", ge.Password, "gid 2 password entry is not set to x")
			assert.ElementsMatch(t, []string{"root", "bin", "daemon"}, ge.Members, "gid 2 members should contain root, bin, and daemon users")
			found_daemon = true
		}

		if ge.GID == 65534 {
			assert.Equal(t, "nobody", ge.GroupName, "gid 65534 is not nobody")
			assert.Equal(t, "x", ge.Password, "gid 65534 password entry is not set to x")
			// XXX if there's no users listed as group members, Parse
			// returns a list with one empty string as a result, not
			// sure if that's intended behavior.
			assert.Equal(t, []string{""}, ge.Members, "gid 65534 members should be empty")
			found_nobody = true
		}
	}

	assert.True(t, found_root, "group file should contain the root group")
	assert.True(t, found_daemon, "group file should contain the daemon group")
	assert.True(t, found_nobody, "group file should contain the nobody group")
}

// TestGroupParseGIDRange is the /etc/group side of TestParseIDRange: a gid of
// 2^32 must not become the root group.
func TestGroupParseGIDRange(t *testing.T) {
	cases := []struct {
		name     string
		line     string
		gid      uint32
		errMatch string
	}{
		{"control", "nginx:x:101:nginx", 101, ""},
		{"max gid", "big:x:4294967295:", 4294967295, ""},
		{"gid 2^32", "backdoor:x:4294967296:", 0, `GID "4294967296"`},
		{"negative gid", "backdoor:x:-1:", 0, `GID "-1"`},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			ge := GroupEntry{}
			err := ge.Parse(tt.line)
			if tt.errMatch != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMatch)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.gid, ge.GID)
		})
	}
}

func TestGroupWriter(t *testing.T) {
	fsys := apkfs.DirFS(t.Context(), "testdata")
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
