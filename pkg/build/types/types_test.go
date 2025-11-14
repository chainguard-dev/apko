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

package types

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestYamlMarshallingRepositories(t *testing.T) {
	const alpineMain = "https://dl-cdn.alpinelinux.org/alpine/v3.22/main"
	const alpineCommunity = "https://dl-cdn.alpinelinux.org/alpine/v3.22/community"
	const alpineEdgeTesting = "https://dl-cdn.alpinelinux.org/alpine/edge/testing"
	const alpineEdgeCommunity = "https://dl-cdn.alpinelinux.org/alpine/edge/community"
	const alpineWithCreds = "https://user:pass@dl-cdn.my.org/alpine/v3.22/main"

	for _, c := range []struct {
		desc string
		in   ImageContents
		want string
	}{{
		desc: "empty",
		in:   ImageContents{},
		want: "{}\n",
	}, {
		desc: "simple",
		in: ImageContents{
			Repositories:      []string{alpineMain, alpineCommunity},
			BuildRepositories: []string{alpineMain, alpineCommunity},
		},
		want: fmt.Sprintf("build_repositories:\n    - %s\n    - %s\nrepositories:\n    - %s\n    - %s\n", alpineMain, alpineCommunity, alpineMain, alpineCommunity),
	}, {
		desc: "tagged",
		in: ImageContents{
			Repositories:      []string{"@testing " + alpineEdgeTesting},
			BuildRepositories: []string{"@community " + alpineEdgeCommunity},
		},
		want: fmt.Sprintf("build_repositories:\n    - '@community %s'\nrepositories:\n    - '@testing %s'\n", alpineEdgeCommunity, alpineEdgeTesting),
	}, {
		desc: "tagged with creds",
		in: ImageContents{
			Repositories: []string{"@myorg " + alpineWithCreds},
		},
		want: fmt.Sprintf("repositories:\n    - '@myorg %s'\n", "https://user:xxxxx@dl-cdn.my.org/alpine/v3.22/main"),
	}, {
		desc: "invalid tag format - missing @",
		in: ImageContents{
			Repositories: []string{"testing https://dl-cdn.alpinelinux.org/alpine/edge/testing"},
		},
		want: "error", // This will cause an error during marshalling
	}, {
		desc: "invalid tag format - empty tag",
		in: ImageContents{
			Repositories: []string{"@ https://dl-cdn.alpinelinux.org/alpine/edge/testing"},
		},
		want: "error", // This will cause an error during marshalling
	}, {
		desc: "invalid URL in tagged repository",
		in: ImageContents{
			Repositories: []string{"@testing ://invalid-url"},
		},
		want: "error", // This will cause an error during marshalling
	}, {
		desc: "invalid URL in untagged repository",
		in: ImageContents{
			Repositories: []string{"://invalid-url"},
		},
		want: "error", // This will cause an error during marshalling
	}, {
		desc: "too many parts in repository",
		in: ImageContents{
			Repositories: []string{"@testing https://example.com extra-part"},
		},
		want: "error", // This will cause an error during marshalling
	}} {
		t.Run(c.desc, func(t *testing.T) {
			b, err := yaml.Marshal(c.in)
			if c.want == "error" {
				require.Error(t, err, "expected error for invalid repository format")
			} else {
				require.NoError(t, err)
				require.Equal(t, c.want, string(b))
			}
		})
	}
}

func TestParseArchitectures(t *testing.T) {
	for _, c := range []struct {
		desc string
		in   []string
		want []Architecture
	}{{
		desc: "empty",
		in:   []string{},
		want: []Architecture{},
	}, {
		desc: "sort",
		in:   []string{"riscv64", "amd64", "arm/v6"},
		want: []Architecture{amd64, armv6, riscv64},
	}, {
		desc: "dedupe",
		in:   []string{"amd64", "amd64", "arm64"},
		want: []Architecture{amd64, arm64},
	}, {
		desc: "dedupe w/ apk style",
		in:   []string{"x86_64", "amd64", "arm64", "arm/v6", "armhf"},
		want: []Architecture{amd64, armv6, arm64},
	}, {
		// Unknown arch strings are accepted.
		desc: "unknown arch",
		in:   []string{"apples", "bananas"},
		want: []Architecture{"apples", "bananas"},
	}, {
		desc: "all",
		in:   []string{"all"},
		want: AllArchs,
	}, {
		// If 'all' is present and isn't the only element, it will be interpreted as an architecture.
		desc: "uh oh all",
		in:   []string{"all", "riscv64"},
		want: []Architecture{"all", riscv64},
	}} {
		t.Run(c.desc, func(t *testing.T) {
			got := ParseArchitectures(c.in)
			require.Equal(t, c.want, got)
		})
	}
}

func TestOCIPlatform(t *testing.T) {
	for _, c := range []struct {
		desc string
		in   string
		want string
	}{{
		desc: "x86_64",
		in:   "x86_64",
		want: "amd64",
	}, {
		desc: "amd64",
		in:   "amd64",
		want: "amd64",
	}, {
		desc: "arm64",
		in:   "arm64",
		want: "arm64",
	}, {
		desc: "aarch64",
		in:   "aarch64",
		want: "arm64",
	}} {
		t.Run(c.desc, func(t *testing.T) {
			got := Architecture(c.in)
			require.Equal(t, c.want, got.ToOCIPlatform().Architecture)
		})
	}
}

var (
	id0     = uint32(0)
	id0T    = GID(&id0)
	id1234  = uint32(1234)
	id1235  = uint32(1235)
	id1235T = GID(&id1235)
)

// Ensure unmarshalling YAML into an ImageConfiguration
// does not result in unexpected GID=0
func Test_YAML_Unmarshalling_UID_GID_mapping(t *testing.T) {
	for _, test := range []struct {
		desc        string
		expectedUID uint32
		expectedGID GID
		rawYAML     string
	}{
		{
			desc:        "Unique GID gets propagated",
			expectedUID: id1234,
			expectedGID: id1235T,
			rawYAML: `
accounts:
  users:
    - username: testing
      uid: 1234
      gid: 1235
`,
		},
		{
			desc:        "Nil GID is treated as nil (not 0)",
			expectedUID: id1234,
			expectedGID: nil,
			rawYAML: `
accounts:
  users:
    - username: testing
      uid: 1234
`,
		},
		{
			desc:        "Able to set GID to 0",
			expectedUID: id1234,
			expectedGID: id0T,
			rawYAML: `
accounts:
  users:
    - username: testing
      uid: 1234
      gid: 0
`,
		},
		{
			// TODO: This may be unintentional but matches historical behavior
			desc:        "Missing UID and GID means UID is 0 and GID is nil",
			expectedUID: 0,
			expectedGID: nil,
			rawYAML: `
accounts:
  users:
    - username: testing
`,
		},
	} {
		var ic ImageConfiguration
		if err := yaml.Unmarshal([]byte(test.rawYAML), &ic); err != nil {
			t.Errorf("%s: unable to unmarshall: %v", test.desc, err)
			continue
		}
		if numUsers := len(ic.Accounts.Users); numUsers != 1 {
			t.Errorf("%s: expected 1 user, got %d", test.desc, numUsers)
			continue
		}
		user := ic.Accounts.Users[0]
		if test.expectedUID != user.UID {
			t.Errorf("%s: expected UID %d got UID %d", test.desc, test.expectedUID, user.UID)
		}
		if diff := cmp.Diff(test.expectedGID, user.GID); diff != "" {
			t.Errorf("%s: diff in GID: (-want, +got) = %s", test.desc, diff)
		}
	}
}

// Ensure marshalling YAML from a User
// does not result in unexpected GID=0
func Test_YAML_Marshalling_UID_GID_mapping(t *testing.T) {
	for _, test := range []struct {
		desc         string
		user         User
		expectedYAML string
	}{
		{
			desc: "Unique UID and GID",
			user: User{
				UserName: "testing",
				UID:      id1234,
				GID:      id1235T,
			},
			expectedYAML: `
username: testing
uid: 1234
gid: 1235
shell: ""
homedir: ""
`,
		},
		{
			desc: "Nil GID gets omitted",
			user: User{
				UserName: "testing",
				UID:      id1234,
			},
			expectedYAML: `
username: testing
uid: 1234
shell: ""
homedir: ""
`,
		},
		{
			desc: "Able to set GID to 0",
			user: User{
				UserName: "testing",
				UID:      id1234,
				GID:      id0T,
			},
			expectedYAML: `
username: testing
uid: 1234
gid: 0
shell: ""
homedir: ""
`,
		},
		{
			// TODO: This may be unintentional but matches historical behavior
			desc: "Missing UID and GID means UID is 0 and GID gets omitted",
			user: User{
				UserName: "testing",
			},
			expectedYAML: `
username: testing
uid: 0
shell: ""
homedir: ""
`,
		},
	} {
		b, err := yaml.Marshal(test.user)
		if err != nil {
			t.Errorf("%s: unable to marshall: %v", test.desc, err)
			continue
		}
		if diff := cmp.Diff(strings.TrimPrefix(test.expectedYAML, "\n"), string(b)); diff != "" {
			t.Errorf("%s: diff in marshalled user YAML: (-want, +got) = %s", test.desc, diff)
		}
	}
}
