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

// TestParseIDRange pins the uid/gid range check. Before it, 2^32 parsed and
// truncated to 0 and -1 wrapped to 4294967295, so a passwd line from a
// package could turn into a root entry in the generated /etc/passwd.
func TestParseIDRange(t *testing.T) {
	cases := []struct {
		name     string
		line     string
		uid, gid uint32
		errMatch string
	}{
		{"control", "nginx:x:100:101:nginx:/var/lib/nginx:/sbin/nologin", 100, 101, ""},
		{"max uid and gid", "big:x:4294967295:4294967295::/:/sbin/nologin", 4294967295, 4294967295, ""},
		{"uid 2^32", "backdoor:x:4294967296:100:svc:/var/lib/svc:/sbin/nologin", 0, 0, `UID "4294967296"`},
		{"negative uid", "backdoor:x:-1:100:svc:/var/lib/svc:/sbin/nologin", 0, 0, `UID "-1"`},
		{"gid 2^32", "backdoor:x:100:4294967296:svc:/var/lib/svc:/sbin/nologin", 0, 0, `GID "4294967296"`},
		{"negative gid", "backdoor:x:100:-1:svc:/var/lib/svc:/sbin/nologin", 0, 0, `GID "-1"`},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			ue := UserEntry{}
			err := ue.Parse(tt.line)
			if tt.errMatch != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMatch)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.uid, ue.UID)
			assert.Equal(t, tt.gid, ue.GID)

			w := &bytes.Buffer{}
			require.NoError(t, ue.Write(w))
			assert.Equal(t, tt.line+"\n", w.String(), "entry should round-trip unchanged")
		})
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
