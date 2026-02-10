// Copyright 2024-2026 Chainguard, Inc.
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

package build

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/passwd"
)

var (
	id0     = uint32(0)
	id0T    = types.GID(&id0)
	id1234  = uint32(1234)
	id1235  = uint32(1235)
	id1235T = types.GID(&id1235)
)

func Test_userToUserEntry_UID_GID_mapping(t *testing.T) {
	for _, test := range []struct {
		desc        string
		user        types.User
		expectedUID uint32
		expectedGID uint32
	}{
		{
			desc: "Unique GID gets propagated",
			user: types.User{
				UID: id1234,
				GID: id1235T,
			},
			expectedUID: id1234,
			expectedGID: id1235,
		},
		{
			desc: "Nil GID defaults to UID",
			user: types.User{
				UID: id1234,
			},
			expectedUID: id1234,
			expectedGID: id1234,
		},
		{
			desc: "Able to set GID to 0",
			user: types.User{
				UID: id1234,
				GID: id0T,
			},
			expectedUID: id1234,
			expectedGID: id0,
		},
		{
			// TODO: This may be unintentional but matches historical behavior
			desc:        "Missing UID and GID means both are 0",
			user:        types.User{},
			expectedUID: id0,
			expectedGID: id0,
		},
	} {
		userEntry := userToUserEntry(test.user)
		if userEntry.UID != test.expectedUID {
			t.Errorf("%s: expected UID %d got UID %d", test.desc, test.expectedUID, userEntry.UID)
		}
		if userEntry.GID != test.expectedGID {
			t.Errorf("%s: expected GID %d got GID %d", test.desc, test.expectedGID, userEntry.GID)
		}
	}
}

func Test_userToShadowEntry(t *testing.T) {
	tests := []struct {
		name string
		user types.User
	}{
		{
			name: "basic user",
			user: types.User{
				UserName: "testuser",
				UID:      id1234,
			},
		},
		{
			name: "user with all fields",
			user: types.User{
				UserName: "testuser",
				UID:      id1234,
				GID:      id1235T,
				Shell:    "/bin/bash",
				HomeDir:  "/home/testuser",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			se := userToShadowEntry(tt.user)

			// Verify username matches
			assert.Equal(t, tt.user.UserName, se.UserName, "username should match")

			// Verify password is locked and invalid
			assert.Equal(t, "!*", se.Password, "password should be !* (locked + invalid)")

			// Verify all numeric fields are nil (empty)
			assert.Nil(t, se.LastChange, "LastChange should be nil")
			assert.Nil(t, se.MinDays, "MinDays should be nil")
			assert.Nil(t, se.MaxDays, "MaxDays should be nil")
			assert.Nil(t, se.WarnDays, "WarnDays should be nil")
			assert.Nil(t, se.InactDays, "InactDays should be nil")
			assert.Nil(t, se.ExpireDate, "ExpireDate should be nil")

			// Verify reserved field is empty
			assert.Empty(t, se.Reserved, "Reserved field should be empty")
		})
	}
}

func Test_groupToGShadowEntry(t *testing.T) {
	tests := []struct {
		name  string
		group types.Group
	}{
		{
			name: "group without members",
			group: types.Group{
				GroupName: "testgroup",
				GID:       id1234,
				Members:   []string{},
			},
		},
		{
			name: "group with single member",
			group: types.Group{
				GroupName: "testgroup",
				GID:       id1234,
				Members:   []string{"user1"},
			},
		},
		{
			name: "group with multiple members",
			group: types.Group{
				GroupName: "testgroup",
				GID:       id1234,
				Members:   []string{"user1", "user2", "user3"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ge := groupToGShadowEntry(tt.group)

			// Verify group name matches
			assert.Equal(t, tt.group.GroupName, ge.GroupName, "group name should match")

			// Verify password is locked and invalid
			assert.Equal(t, "!*", ge.Password, "password should be !* (locked + invalid)")

			// Verify administrators is empty
			assert.Equal(t, []string{""}, ge.Administrators, "administrators should be empty ([]string{\"\"})")

			// Verify members match
			assert.Equal(t, tt.group.Members, ge.Members, "members should match")
		})
	}
}

func Test_mutateAccounts(t *testing.T) {
	tests := []struct {
		name   string
		config *types.ImageConfiguration
	}{
		{
			name: "with users only",
			config: &types.ImageConfiguration{
				Accounts: types.ImageAccounts{
					Users: []types.User{
						{
							UserName: "testuser1",
							UID:      1000,
						},
						{
							UserName: "testuser2",
							UID:      1001,
							GID:      &id1235,
						},
					},
				},
			},
		},
		{
			name: "with groups only",
			config: &types.ImageConfiguration{
				Accounts: types.ImageAccounts{
					Groups: []types.Group{
						{
							GroupName: "testgroup1",
							GID:       2000,
							Members:   []string{"user1"},
						},
						{
							GroupName: "testgroup2",
							GID:       2001,
							Members:   []string{"user1", "user2"},
						},
					},
				},
			},
		},
		{
			name: "with both users and groups",
			config: &types.ImageConfiguration{
				Accounts: types.ImageAccounts{
					Users: []types.User{
						{
							UserName: "testuser",
							UID:      1000,
						},
					},
					Groups: []types.Group{
						{
							GroupName: "testgroup",
							GID:       2000,
							Members:   []string{"testuser"},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := apkfs.NewMemFS()

			// Create etc directory
			err := fsys.MkdirAll("etc", 0o755)
			require.NoError(t, err)

			// Run mutateAccounts
			err = mutateAccounts(fsys, tt.config)
			require.NoError(t, err)

			// Check /etc/passwd if users were added
			if len(tt.config.Accounts.Users) > 0 {
				uf, err := passwd.ReadUserFile(fsys, filepath.Join("etc", "passwd"))
				require.NoError(t, err)
				assert.Len(t, uf.Entries, len(tt.config.Accounts.Users), "passwd should have correct number of entries")

				// Verify each user entry
				for i, user := range tt.config.Accounts.Users {
					assert.Equal(t, user.UserName, uf.Entries[i].UserName, "username should match")
					assert.Equal(t, user.UID, uf.Entries[i].UID, "UID should match")
					assert.Equal(t, "x", uf.Entries[i].Password, "password should be 'x' (shadow file)")
				}
			}

			// Check /etc/shadow if users were added
			if len(tt.config.Accounts.Users) > 0 {
				sf, err := passwd.ReadShadowFile(fsys, filepath.Join("etc", "shadow"))
				require.NoError(t, err)
				assert.Len(t, sf.Entries, len(tt.config.Accounts.Users), "shadow should have correct number of entries")

				// Verify each shadow entry
				for i, user := range tt.config.Accounts.Users {
					assert.Equal(t, user.UserName, sf.Entries[i].UserName, "username should match")
					assert.Equal(t, "!*", sf.Entries[i].Password, "password should be '!*' (locked + invalid)")
					assert.Nil(t, sf.Entries[i].LastChange, "LastChange should be nil")
					assert.Nil(t, sf.Entries[i].MinDays, "MinDays should be nil")
					assert.Nil(t, sf.Entries[i].MaxDays, "MaxDays should be nil")
					assert.Nil(t, sf.Entries[i].WarnDays, "WarnDays should be nil")
					assert.Nil(t, sf.Entries[i].InactDays, "InactDays should be nil")
					assert.Nil(t, sf.Entries[i].ExpireDate, "ExpireDate should be nil")
				}
			}

			// Check /etc/group if groups were added
			if len(tt.config.Accounts.Groups) > 0 {
				gf, err := passwd.ReadGroupFile(fsys, filepath.Join("etc", "group"))
				require.NoError(t, err)
				assert.Len(t, gf.Entries, len(tt.config.Accounts.Groups), "group should have correct number of entries")

				// Verify each group entry
				for i, group := range tt.config.Accounts.Groups {
					assert.Equal(t, group.GroupName, gf.Entries[i].GroupName, "group name should match")
					assert.Equal(t, group.GID, gf.Entries[i].GID, "GID should match")
					assert.Equal(t, "x", gf.Entries[i].Password, "password should be 'x' (gshadow file)")
					assert.Equal(t, group.Members, gf.Entries[i].Members, "members should match")
				}
			}

			// Check /etc/gshadow if groups were added
			if len(tt.config.Accounts.Groups) > 0 {
				gf, err := passwd.ReadGShadowFile(fsys, filepath.Join("etc", "gshadow"))
				require.NoError(t, err)
				assert.Len(t, gf.Entries, len(tt.config.Accounts.Groups), "gshadow should have correct number of entries")

				// Verify each gshadow entry
				for i, group := range tt.config.Accounts.Groups {
					assert.Equal(t, group.GroupName, gf.Entries[i].GroupName, "group name should match")
					assert.Equal(t, "!*", gf.Entries[i].Password, "password should be '!*' (locked + invalid)")
					assert.Equal(t, []string{""}, gf.Entries[i].Administrators, "administrators should be empty")
					assert.Equal(t, group.Members, gf.Entries[i].Members, "members should match")
				}
			}
		})
	}
}

func Test_mutateAccounts_emptyConfig(t *testing.T) {
	fsys := apkfs.NewMemFS()

	// Create etc directory
	err := fsys.MkdirAll("etc", 0o755)
	require.NoError(t, err)

	// Run mutateAccounts with empty config
	config := &types.ImageConfiguration{
		Accounts: types.ImageAccounts{
			Users:  []types.User{},
			Groups: []types.Group{},
		},
	}

	err = mutateAccounts(fsys, config)
	require.NoError(t, err)

	// Verify files are created but empty
	uf, err := passwd.ReadUserFile(fsys, filepath.Join("etc", "passwd"))
	require.NoError(t, err)
	assert.Empty(t, uf.Entries, "passwd should be empty")

	sf, err := passwd.ReadShadowFile(fsys, filepath.Join("etc", "shadow"))
	require.NoError(t, err)
	assert.Empty(t, sf.Entries, "shadow should be empty")
}
