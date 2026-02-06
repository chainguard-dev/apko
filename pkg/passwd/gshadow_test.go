// Copyright 2026 Chainguard, Inc.
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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
)

func TestGShadowParser(t *testing.T) {
	// Test with MemFS approach
	t.Run("MemFS", func(t *testing.T) {
		fsys := apkfs.NewMemFS()
		gshadow, err := os.ReadFile("testdata/gshadow")
		require.NoError(t, err)
		err = fsys.MkdirAll("etc", 0o755)
		require.NoError(t, err)
		err = fsys.WriteFile("etc/gshadow", gshadow, 0o640)
		require.NoError(t, err)
		gf, err := ReadOrCreateGShadowFile(fsys, "etc/gshadow")
		require.NoError(t, err)
		require.NotEmpty(t, gf, "parsed gshadow file should not be empty")

		validateGShadowEntries(t, gf.Entries)
	})

	// Test with DirFS approach
	t.Run("DirFS", func(t *testing.T) {
		fsys := apkfs.DirFS(t.Context(), "testdata")
		gf, err := ReadGShadowFile(fsys, "gshadow")
		require.NoError(t, err)
		require.NotEmpty(t, gf, "parsed gshadow file should not be empty")

		validateGShadowEntries(t, gf.Entries)
	})

	// Test ReadOrCreate vs Read behavior
	t.Run("ReadOrCreate creates missing file", func(t *testing.T) {
		fsys := apkfs.NewMemFS()
		err := fsys.MkdirAll("etc", 0o755)
		require.NoError(t, err)
		gf, err := ReadOrCreateGShadowFile(fsys, "etc/gshadow")
		require.NoError(t, err)
		assert.Empty(t, gf.Entries, "new gshadow file should be empty")
	})

	t.Run("Read fails on missing file", func(t *testing.T) {
		fsys := apkfs.NewMemFS()
		_, err := ReadGShadowFile(fsys, "etc/gshadow")
		require.Error(t, err, "ReadGShadowFile should fail on missing file")
	})
}

func validateGShadowEntries(t *testing.T, entries []GShadowEntry) {
	found_root := false
	found_daemon := false
	found_sys := false
	found_adm := false
	found_wheel := false

	for _, ge := range entries {
		switch ge.GroupName {
		case "root":
			assert.Equal(t, "*", ge.Password, "root password should be *")
			assert.Equal(t, []string{""}, ge.Administrators, "root administrators should be empty ([]string{\"\"})")
			assert.Equal(t, []string{"root"}, ge.Members, "root members should contain root")
			found_root = true

		case "daemon":
			assert.Equal(t, "!", ge.Password, "daemon password should be !")
			assert.Equal(t, []string{""}, ge.Administrators, "daemon administrators should be empty")
			assert.ElementsMatch(t, []string{"bin", "daemon"}, ge.Members, "daemon members should contain bin and daemon")
			found_daemon = true

		case "sys":
			assert.Equal(t, "!", ge.Password, "sys password should be !")
			assert.Equal(t, []string{""}, ge.Administrators, "sys administrators should be empty")
			assert.Equal(t, []string{""}, ge.Members, "sys members should be empty ([]string{\"\"})")
			found_sys = true

		case "adm":
			assert.Equal(t, "!", ge.Password, "adm password should be !")
			assert.Equal(t, []string{"root"}, ge.Administrators, "adm should have root as administrator")
			assert.ElementsMatch(t, []string{"adm", "daemon"}, ge.Members, "adm members should contain adm and daemon")
			found_adm = true

		case "wheel":
			assert.Equal(t, "!", ge.Password, "wheel password should be !")
			assert.Equal(t, []string{"root"}, ge.Administrators, "wheel should have root as administrator")
			assert.Equal(t, []string{""}, ge.Members, "wheel members should be empty")
			found_wheel = true
		}
	}

	assert.True(t, found_root, "gshadow file should contain root group")
	assert.True(t, found_daemon, "gshadow file should contain daemon group")
	assert.True(t, found_sys, "gshadow file should contain sys group")
	assert.True(t, found_adm, "gshadow file should contain adm group")
	assert.True(t, found_wheel, "gshadow file should contain wheel group")
}

func TestGShadowWriter(t *testing.T) {
	// Test MemFS round-trip
	t.Run("MemFS round-trip", func(t *testing.T) {
		fsys := apkfs.NewMemFS()
		gshadow, err := os.ReadFile("testdata/gshadow")
		require.NoError(t, err)
		err = fsys.MkdirAll("etc", 0o755)
		require.NoError(t, err)
		err = fsys.WriteFile("etc/gshadow", gshadow, 0o640)
		require.NoError(t, err)

		gf, err := ReadOrCreateGShadowFile(fsys, "etc/gshadow")
		require.NoError(t, err)

		w := &bytes.Buffer{}
		require.NoError(t, gf.Write(w))

		r := bytes.NewReader(w.Bytes())
		gf2 := &GShadowFile{}
		require.NoError(t, gf2.Load(r))

		w2 := &bytes.Buffer{}
		require.NoError(t, gf2.Write(w2))

		assert.Equal(t, w.Bytes(), w2.Bytes(), "round-trip should produce identical output")
	})

	// Test buffer round-trip (no filesystem)
	t.Run("Buffer round-trip", func(t *testing.T) {
		gshadow, err := os.ReadFile("testdata/gshadow")
		require.NoError(t, err)

		gf := &GShadowFile{}
		require.NoError(t, gf.Load(bytes.NewReader(gshadow)))

		w := &bytes.Buffer{}
		require.NoError(t, gf.Write(w))

		gf2 := &GShadowFile{}
		require.NoError(t, gf2.Load(bytes.NewReader(w.Bytes())))

		w2 := &bytes.Buffer{}
		require.NoError(t, gf2.Write(w2))

		assert.Equal(t, w.Bytes(), w2.Bytes(), "buffer round-trip should produce identical output")
	})

	// Test mixed filesystem operations
	t.Run("Mixed filesystem operations", func(t *testing.T) {
		// Read from DirFS
		dirFS := apkfs.DirFS(t.Context(), "testdata")
		gf, err := ReadGShadowFile(dirFS, "gshadow")
		require.NoError(t, err)

		// Write to MemFS
		memFS := apkfs.NewMemFS()
		err = memFS.MkdirAll("etc", 0o755)
		require.NoError(t, err)
		err = gf.WriteFile(memFS, "etc/gshadow")
		require.NoError(t, err)

		// Read back from MemFS
		gf2, err := ReadGShadowFile(memFS, "etc/gshadow")
		require.NoError(t, err)

		// Compare entries
		assert.Equal(t, len(gf.Entries), len(gf2.Entries), "entry count should match")
		for i := range gf.Entries {
			assert.Equal(t, gf.Entries[i].GroupName, gf2.Entries[i].GroupName, "groupnames should match")
			assert.Equal(t, gf.Entries[i].Password, gf2.Entries[i].Password, "passwords should match")
		}
	})
}

func TestGShadowParseLine(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		want    GShadowEntry
		wantErr bool
	}{
		{
			name: "group with multiple members",
			line: "daemon:!::bin,daemon",
			want: GShadowEntry{
				GroupName:      "daemon",
				Password:       "!",
				Administrators: []string{""},
				Members:        []string{"bin", "daemon"},
			},
		},
		{
			name: "group with admin and members",
			line: "adm:!:root:adm,daemon",
			want: GShadowEntry{
				GroupName:      "adm",
				Password:       "!",
				Administrators: []string{"root"},
				Members:        []string{"adm", "daemon"},
			},
		},
		{
			name: "group with admin only",
			line: "wheel:!:root:",
			want: GShadowEntry{
				GroupName:      "wheel",
				Password:       "!",
				Administrators: []string{"root"},
				Members:        []string{""},
			},
		},
		{
			name: "group with empty fields",
			line: "sys:!::",
			want: GShadowEntry{
				GroupName:      "sys",
				Password:       "!",
				Administrators: []string{""},
				Members:        []string{""},
			},
		},
		{
			name: "group with asterisk password",
			line: "root:*::root",
			want: GShadowEntry{
				GroupName:      "root",
				Password:       "*",
				Administrators: []string{""},
				Members:        []string{"root"},
			},
		},
		{
			name: "group with empty password",
			line: "test:::user1,user2",
			want: GShadowEntry{
				GroupName:      "test",
				Password:       "",
				Administrators: []string{""},
				Members:        []string{"user1", "user2"},
			},
		},
		{
			name: "group with single member",
			line: "sshd:!::sshd",
			want: GShadowEntry{
				GroupName:      "sshd",
				Password:       "!",
				Administrators: []string{""},
				Members:        []string{"sshd"},
			},
		},
		{
			name: "group with multiple admins",
			line: "sudo:!:root,admin:user1,user2",
			want: GShadowEntry{
				GroupName:      "sudo",
				Password:       "!",
				Administrators: []string{"root", "admin"},
				Members:        []string{"user1", "user2"},
			},
		},
		{
			name:    "wrong field count - too few",
			line:    "group:!:admin",
			wantErr: true,
		},
		{
			name:    "wrong field count - too many",
			line:    "group:!:admin:members:extra",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ge := &GShadowEntry{}
			err := ge.Parse(tt.line)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want.GroupName, ge.GroupName)
			assert.Equal(t, tt.want.Password, ge.Password)
			assert.Equal(t, tt.want.Administrators, ge.Administrators)
			assert.Equal(t, tt.want.Members, ge.Members)
		})
	}
}

func TestGShadowWriteLine(t *testing.T) {
	tests := []struct {
		name string
		ge   GShadowEntry
		want string
	}{
		{
			name: "full entry",
			ge: GShadowEntry{
				GroupName:      "adm",
				Password:       "!",
				Administrators: []string{"root"},
				Members:        []string{"adm", "daemon"},
			},
			want: "adm:!:root:adm,daemon\n",
		},
		{
			name: "entry with empty lists",
			ge: GShadowEntry{
				GroupName:      "sys",
				Password:       "!",
				Administrators: []string{""},
				Members:        []string{""},
			},
			want: "sys:!::\n",
		},
		{
			name: "entry with multiple admins and members",
			ge: GShadowEntry{
				GroupName:      "sudo",
				Password:       "!",
				Administrators: []string{"root", "admin"},
				Members:        []string{"user1", "user2", "user3"},
			},
			want: "sudo:!:root,admin:user1,user2,user3\n",
		},
		{
			name: "entry with admin only",
			ge: GShadowEntry{
				GroupName:      "wheel",
				Password:       "!",
				Administrators: []string{"root"},
				Members:        []string{""},
			},
			want: "wheel:!:root:\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &bytes.Buffer{}
			err := tt.ge.Write(w)
			require.NoError(t, err)
			assert.Equal(t, tt.want, w.String())
		})
	}
}

func TestGShadowParseErrors(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		wantErr string
	}{
		{
			name:    "no colons",
			line:    "justtext",
			wantErr: "contains 1 parts, expecting 4",
		},
		{
			name:    "only colons",
			line:    ":::",
			wantErr: "", // should parse successfully
		},
		{
			name:    "3 fields",
			line:    "group:!:admin",
			wantErr: "contains 3 parts, expecting 4",
		},
		{
			name:    "5 fields",
			line:    "group:!:admin:members:extra",
			wantErr: "contains 5 parts, expecting 4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ge := &GShadowEntry{}
			err := ge.Parse(tt.line)

			if tt.wantErr == "" && tt.name == "only colons" {
				// Special case: should parse successfully
				require.NoError(t, err)
				return
			}

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestGShadowEdgeCases(t *testing.T) {
	t.Run("empty file", func(t *testing.T) {
		gf := &GShadowFile{}
		err := gf.Load(strings.NewReader(""))
		require.NoError(t, err)
		assert.Empty(t, gf.Entries)
	})

	t.Run("single entry", func(t *testing.T) {
		gf := &GShadowFile{}
		err := gf.Load(strings.NewReader("root:*::root\n"))
		require.NoError(t, err)
		assert.Len(t, gf.Entries, 1)
		assert.Equal(t, "root", gf.Entries[0].GroupName)
	})

	t.Run("empty string split behavior", func(t *testing.T) {
		ge := &GShadowEntry{}
		err := ge.Parse("test:!::")
		require.NoError(t, err)
		// Verify that strings.Split("", ",") returns []string{""}
		assert.Equal(t, []string{""}, ge.Administrators, "empty administrators should be []string{\"\"}")
		assert.Equal(t, []string{""}, ge.Members, "empty members should be []string{\"\"}")
	})

	t.Run("single vs multiple members", func(t *testing.T) {
		// Single member
		ge1 := &GShadowEntry{}
		err := ge1.Parse("group:!::user1")
		require.NoError(t, err)
		assert.Equal(t, []string{"user1"}, ge1.Members)

		// Multiple members
		ge2 := &GShadowEntry{}
		err = ge2.Parse("group:!::user1,user2,user3")
		require.NoError(t, err)
		assert.Equal(t, []string{"user1", "user2", "user3"}, ge2.Members)
	})

	t.Run("various password values", func(t *testing.T) {
		tests := []struct {
			line string
			pass string
		}{
			{"group:!::members", "!"},
			{"group:*::members", "*"},
			{"group:::members", ""},
			{"group:!*::members", "!*"},
		}

		for _, tt := range tests {
			ge := &GShadowEntry{}
			err := ge.Parse(tt.line)
			require.NoError(t, err)
			assert.Equal(t, tt.pass, ge.Password)
		}
	})

	t.Run("long member list", func(t *testing.T) {
		members := []string{"user1", "user2", "user3", "user4", "user5", "user6", "user7", "user8", "user9", "user10"}
		line := "group:!::" + strings.Join(members, ",")
		ge := &GShadowEntry{}
		err := ge.Parse(line)
		require.NoError(t, err)
		assert.Equal(t, members, ge.Members)
	})
}
