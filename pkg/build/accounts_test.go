// Copyright 2024 Chainguard, Inc.
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
	"testing"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/build/types"
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

// mutateAccounts reads /etc/passwd, appends the configured users and writes the
// whole file back. Before parseID, a package-shipped line with an out-of-range
// uid parsed cleanly, truncated to 0 and was written back out as a root entry —
// the read-modify-write is what turned a bad parse into a persisted root
// account. The parse error has to propagate out of mutateAccounts instead.
func Test_mutateAccounts_rejectsOutOfRangeUID(t *testing.T) {
	for _, test := range []struct {
		desc   string
		passwd string
	}{
		{"uid 2^32", "backdoor:x:4294967296:0:backdoor:/dev/null:/sbin/nologin\n"},
		{"negative uid", "backdoor:x:-1:0:backdoor:/dev/null:/sbin/nologin\n"},
		{"gid 2^32", "backdoor:x:1000:4294967296:backdoor:/dev/null:/sbin/nologin\n"},
	} {
		t.Run(test.desc, func(t *testing.T) {
			fsys := apkfs.NewMemFS()
			if err := fsys.MkdirAll("etc", 0o755); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
			if err := fsys.WriteFile("etc/passwd", []byte(test.passwd), 0o644); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}

			ic := &types.ImageConfiguration{}
			ic.Accounts.Users = []types.User{{UserName: "nonroot", UID: 65532, GID: id0T}}

			if err := mutateAccounts(fsys, ic); err == nil {
				t.Fatal("mutateAccounts accepted an out-of-range id, want rejection")
			}

			// The bad line must not have been rewritten as a root entry.
			got, err := fsys.ReadFile("etc/passwd")
			if err != nil {
				t.Fatalf("ReadFile: %v", err)
			}
			if string(got) != test.passwd {
				t.Errorf("etc/passwd was rewritten:\n got %q\nwant %q", got, test.passwd)
			}
		})
	}
}
