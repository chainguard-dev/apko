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

func TestShadowParser(t *testing.T) {
	// Test with MemFS approach
	t.Run("MemFS", func(t *testing.T) {
		fsys := apkfs.NewMemFS()
		shadow, err := os.ReadFile("testdata/shadow")
		require.NoError(t, err)
		err = fsys.MkdirAll("etc", 0o755)
		require.NoError(t, err)
		err = fsys.WriteFile("etc/shadow", shadow, 0o640)
		require.NoError(t, err)
		sf, err := ReadOrCreateShadowFile(fsys, "etc/shadow")
		require.NoError(t, err)
		require.NotEmpty(t, sf, "parsed shadow file should not be empty")

		validateShadowEntries(t, sf.Entries)
	})

	// Test with DirFS approach
	t.Run("DirFS", func(t *testing.T) {
		fsys := apkfs.DirFS(t.Context(), "testdata")
		sf, err := ReadShadowFile(fsys, "shadow")
		require.NoError(t, err)
		require.NotEmpty(t, sf, "parsed shadow file should not be empty")

		validateShadowEntries(t, sf.Entries)
	})

	// Test ReadOrCreate vs Read behavior
	t.Run("ReadOrCreate creates missing file", func(t *testing.T) {
		fsys := apkfs.NewMemFS()
		err := fsys.MkdirAll("etc", 0o755)
		require.NoError(t, err)
		sf, err := ReadOrCreateShadowFile(fsys, "etc/shadow")
		require.NoError(t, err)
		assert.Empty(t, sf.Entries, "new shadow file should be empty")
	})

	t.Run("Read fails on missing file", func(t *testing.T) {
		fsys := apkfs.NewMemFS()
		_, err := ReadShadowFile(fsys, "etc/shadow")
		require.Error(t, err, "ReadShadowFile should fail on missing file")
	})
}

func validateShadowEntries(t *testing.T, entries []ShadowEntry) {
	found_root := false
	found_linky := false
	found_coredump := false

	for _, se := range entries {
		switch se.UserName {
		case "root":
			assert.Equal(t, "*", se.Password, "root password should be *")
			assert.Nil(t, se.LastChange, "root lastchange should be empty/nil")
			assert.NotNil(t, se.MinDays, "root mindays should be populated with 0")
			if se.MinDays != nil {
				assert.Equal(t, int64(0), *se.MinDays, "root mindays should be 0")
			}
			assert.Nil(t, se.MaxDays, "root maxdays should be empty/nil")
			assert.Nil(t, se.WarnDays, "root warndays should be empty/nil")
			assert.Nil(t, se.InactDays, "root inactdays should be empty/nil")
			assert.Nil(t, se.ExpireDate, "root expiredate should be empty/nil")
			assert.Empty(t, se.Reserved, "root reserved field should be empty")
			found_root = true

		case "linky":
			assert.True(t, strings.HasPrefix(se.Password, "$6$"), "linky should have hashed password")
			assert.NotNil(t, se.LastChange, "linky lastchange should be populated")
			if se.LastChange != nil {
				assert.Equal(t, int64(20487), *se.LastChange, "linky lastchange should be 20487")
			}
			found_linky = true

		case "systemd-coredump":
			assert.Equal(t, "!*", se.Password, "systemd-coredump password should be !*")
			assert.NotNil(t, se.LastChange, "systemd-coredump lastchange should be populated")
			if se.LastChange != nil {
				assert.Equal(t, int64(20487), *se.LastChange, "systemd-coredump lastchange should be 20487")
			}
			assert.NotNil(t, se.ExpireDate, "systemd-coredump expiredate should be set")
			if se.ExpireDate != nil {
				assert.Equal(t, int64(1), *se.ExpireDate, "systemd-coredump expiredate should be 1")
			}
			found_coredump = true
		}
	}

	assert.True(t, found_root, "shadow file should contain root user")
	assert.True(t, found_linky, "shadow file should contain linky user")
	assert.True(t, found_coredump, "shadow file should contain systemd-coredump user")
}

func TestShadowWriter(t *testing.T) {
	// Test MemFS round-trip
	t.Run("MemFS round-trip", func(t *testing.T) {
		fsys := apkfs.NewMemFS()
		shadow, err := os.ReadFile("testdata/shadow")
		require.NoError(t, err)
		err = fsys.MkdirAll("etc", 0o755)
		require.NoError(t, err)
		err = fsys.WriteFile("etc/shadow", shadow, 0o640)
		require.NoError(t, err)

		sf, err := ReadOrCreateShadowFile(fsys, "etc/shadow")
		require.NoError(t, err)

		w := &bytes.Buffer{}
		require.NoError(t, sf.Write(w))

		r := bytes.NewReader(w.Bytes())
		sf2 := &ShadowFile{}
		require.NoError(t, sf2.Load(r))

		w2 := &bytes.Buffer{}
		require.NoError(t, sf2.Write(w2))

		assert.Equal(t, w.Bytes(), w2.Bytes(), "round-trip should produce identical output")
	})

	// Test buffer round-trip (no filesystem)
	t.Run("Buffer round-trip", func(t *testing.T) {
		shadow, err := os.ReadFile("testdata/shadow")
		require.NoError(t, err)

		sf := &ShadowFile{}
		require.NoError(t, sf.Load(bytes.NewReader(shadow)))

		w := &bytes.Buffer{}
		require.NoError(t, sf.Write(w))

		sf2 := &ShadowFile{}
		require.NoError(t, sf2.Load(bytes.NewReader(w.Bytes())))

		w2 := &bytes.Buffer{}
		require.NoError(t, sf2.Write(w2))

		assert.Equal(t, w.Bytes(), w2.Bytes(), "buffer round-trip should produce identical output")
	})

	// Test mixed filesystem operations
	t.Run("Mixed filesystem operations", func(t *testing.T) {
		// Read from DirFS
		dirFS := apkfs.DirFS(t.Context(), "testdata")
		sf, err := ReadShadowFile(dirFS, "shadow")
		require.NoError(t, err)

		// Write to MemFS
		memFS := apkfs.NewMemFS()
		err = memFS.MkdirAll("etc", 0o755)
		require.NoError(t, err)
		err = sf.WriteFile(memFS, "etc/shadow")
		require.NoError(t, err)

		// Read back from MemFS
		sf2, err := ReadShadowFile(memFS, "etc/shadow")
		require.NoError(t, err)

		// Compare entries
		assert.Equal(t, len(sf.Entries), len(sf2.Entries), "entry count should match")
		for i := range sf.Entries {
			assert.Equal(t, sf.Entries[i].UserName, sf2.Entries[i].UserName, "usernames should match")
			assert.Equal(t, sf.Entries[i].Password, sf2.Entries[i].Password, "passwords should match")
		}
	})
}

func TestShadowParseLine(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		want    ShadowEntry
		wantErr bool
	}{
		{
			name: "full entry with hash",
			line: "linky:$6$hash:20487:1:99999:7:30:20000:reserved",
			want: ShadowEntry{
				UserName:   "linky",
				Password:   "$6$hash",
				LastChange: int64Ptr(20487),
				MinDays:    int64Ptr(1),
				MaxDays:    int64Ptr(99999),
				WarnDays:   int64Ptr(7),
				InactDays:  int64Ptr(30),
				ExpireDate: int64Ptr(20000),
				Reserved:   "reserved",
			},
		},
		{
			name: "entry with empty numeric fields",
			line: "root:*::0:::::",
			want: ShadowEntry{
				UserName:   "root",
				Password:   "*",
				LastChange: nil,
				MinDays:    int64Ptr(0),
				MaxDays:    nil,
				WarnDays:   nil,
				InactDays:  nil,
				ExpireDate: nil,
				Reserved:   "",
			},
		},
		{
			name: "locked account (!)",
			line: "user:!:20487::::::",
			want: ShadowEntry{
				UserName:   "user",
				Password:   "!",
				LastChange: int64Ptr(20487),
				MinDays:    nil,
				MaxDays:    nil,
				WarnDays:   nil,
				InactDays:  nil,
				ExpireDate: nil,
				Reserved:   "",
			},
		},
		{
			name: "no login allowed (!*)",
			line: "systemd:!*:20487:::::1:",
			want: ShadowEntry{
				UserName:   "systemd",
				Password:   "!*",
				LastChange: int64Ptr(20487),
				MinDays:    nil,
				MaxDays:    nil,
				WarnDays:   nil,
				InactDays:  nil,
				ExpireDate: int64Ptr(1),
				Reserved:   "",
			},
		},
		{
			name: "empty password field",
			line: "user::20487::::::",
			want: ShadowEntry{
				UserName:   "user",
				Password:   "",
				LastChange: int64Ptr(20487),
				MinDays:    nil,
				MaxDays:    nil,
				WarnDays:   nil,
				InactDays:  nil,
				ExpireDate: nil,
				Reserved:   "",
			},
		},
		{
			name: "all fields populated",
			line: "test:x:19999:0:99999:7:14:20000:res",
			want: ShadowEntry{
				UserName:   "test",
				Password:   "x",
				LastChange: int64Ptr(19999),
				MinDays:    int64Ptr(0),
				MaxDays:    int64Ptr(99999),
				WarnDays:   int64Ptr(7),
				InactDays:  int64Ptr(14),
				ExpireDate: int64Ptr(20000),
				Reserved:   "res",
			},
		},
		{
			name:    "wrong field count - too few",
			line:    "user:*:20487:0",
			wantErr: true,
		},
		{
			name:    "wrong field count - too many",
			line:    "user:*:20487:0:::::::::extra",
			wantErr: true,
		},
		{
			name:    "invalid lastchange value",
			line:    "user:*:notanumber:0:::::",
			wantErr: true,
		},
		{
			name:    "invalid mindays value",
			line:    "user:*:20487:invalid:::::",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			se := &ShadowEntry{}
			err := se.Parse(tt.line)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want.UserName, se.UserName)
			assert.Equal(t, tt.want.Password, se.Password)
			assert.Equal(t, tt.want.LastChange, se.LastChange)
			assert.Equal(t, tt.want.MinDays, se.MinDays)
			assert.Equal(t, tt.want.MaxDays, se.MaxDays)
			assert.Equal(t, tt.want.WarnDays, se.WarnDays)
			assert.Equal(t, tt.want.InactDays, se.InactDays)
			assert.Equal(t, tt.want.ExpireDate, se.ExpireDate)
			assert.Equal(t, tt.want.Reserved, se.Reserved)
		})
	}
}

func TestShadowWriteLine(t *testing.T) {
	tests := []struct {
		name string
		se   ShadowEntry
		want string
	}{
		{
			name: "full entry",
			se: ShadowEntry{
				UserName:   "linky",
				Password:   "$6$hash",
				LastChange: int64Ptr(20487),
				MinDays:    int64Ptr(1),
				MaxDays:    int64Ptr(99999),
				WarnDays:   int64Ptr(7),
				InactDays:  int64Ptr(30),
				ExpireDate: int64Ptr(20000),
				Reserved:   "reserved",
			},
			want: "linky:$6$hash:20487:1:99999:7:30:20000:reserved\n",
		},
		{
			name: "entry with nil fields",
			se: ShadowEntry{
				UserName:   "root",
				Password:   "*",
				LastChange: nil,
				MinDays:    int64Ptr(0),
				MaxDays:    nil,
				WarnDays:   nil,
				InactDays:  nil,
				ExpireDate: nil,
				Reserved:   "",
			},
			want: "root:*::0:::::\n",
		},
		{
			name: "entry with all nil numeric fields",
			se: ShadowEntry{
				UserName:   "test",
				Password:   "!",
				LastChange: nil,
				MinDays:    nil,
				MaxDays:    nil,
				WarnDays:   nil,
				InactDays:  nil,
				ExpireDate: nil,
				Reserved:   "",
			},
			want: "test:!:::::::\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &bytes.Buffer{}
			err := tt.se.Write(w)
			require.NoError(t, err)
			assert.Equal(t, tt.want, w.String())
		})
	}
}

func TestShadowParseErrors(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		wantErr string
	}{
		{
			name:    "no colons",
			line:    "justtext",
			wantErr: "contains 1 parts, expecting 9",
		},
		{
			name:    "only colons",
			line:    "::::::::",
			wantErr: "", // should parse but all fields empty/zero
		},
		{
			name:    "10 fields (too many)",
			line:    "user:*:20487:0::::::extra:more",
			wantErr: "contains 11 parts, expecting 9",
		},
		{
			name:    "invalid lastchange",
			line:    "user:*:abc:0:::::",
			wantErr: "failed to parse LastChange",
		},
		{
			name:    "invalid maxdays",
			line:    "user:*:20487:0:xyz::::",
			wantErr: "failed to parse MaxDays",
		},
		{
			name:    "invalid expiredate",
			line:    "user:*:20487:0::::bad:",
			wantErr: "failed to parse ExpireDate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			se := &ShadowEntry{}
			err := se.Parse(tt.line)

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

func TestShadowEdgeCases(t *testing.T) {
	t.Run("empty file", func(t *testing.T) {
		sf := &ShadowFile{}
		err := sf.Load(strings.NewReader(""))
		require.NoError(t, err)
		assert.Empty(t, sf.Entries)
	})

	t.Run("single entry", func(t *testing.T) {
		sf := &ShadowFile{}
		err := sf.Load(strings.NewReader("root:*::0:::::\n"))
		require.NoError(t, err)
		assert.Len(t, sf.Entries, 1)
		assert.Equal(t, "root", sf.Entries[0].UserName)
	})

	t.Run("large numeric values", func(t *testing.T) {
		se := &ShadowEntry{}
		err := se.Parse("user:*:99999999:0:::::")
		require.NoError(t, err)
		assert.NotNil(t, se.LastChange)
		if se.LastChange != nil {
			assert.Equal(t, int64(99999999), *se.LastChange)
		}
	})

	t.Run("zero values", func(t *testing.T) {
		se := &ShadowEntry{}
		err := se.Parse("user:*:0:0:0:0:0:0:")
		require.NoError(t, err)
		assert.Equal(t, int64(0), *se.LastChange)
		assert.Equal(t, int64(0), *se.MinDays)
		assert.Equal(t, int64(0), *se.MaxDays)
	})
}

// Helper function to create int64 pointers
func int64Ptr(v int64) *int64 {
	return &v
}
