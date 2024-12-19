package types_test

import (
	"context"
	"crypto/sha256"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"chainguard.dev/apko/pkg/build/types"
)

var (
	gid1000  = uint32(1000)
	gid1001  = uint32(1001)
	gid1000T = types.GID(&gid1000)
	gid1001T = types.GID(&gid1001)
)

func TestOverlayWithEmptyContents(t *testing.T) {
	ctx := context.Background()

	configPath := filepath.Join("overlay", "overlay.apko.yaml")
	hasher := sha256.New()
	ic := types.ImageConfiguration{}

	require.NoError(t, ic.Load(ctx, configPath, []string{"testdata"}, hasher))
	require.ElementsMatch(t, ic.Contents.BuildRepositories, []string{"secret repository"})
	require.ElementsMatch(t, ic.Contents.RuntimeRepositories, []string{"repository"})
	require.ElementsMatch(t, ic.Contents.Keyring, []string{"key"})
	require.ElementsMatch(t, ic.Contents.Packages, []string{"package"})
}

func TestOverlayWithAdditionalPackages(t *testing.T) {
	ctx := context.Background()

	configPath := filepath.Join("testdata", "overlay", "overlay_with_package.apko.yaml")
	hasher := sha256.New()
	ic := types.ImageConfiguration{}

	require.NoError(t, ic.Load(ctx, configPath, []string{}, hasher))
	require.ElementsMatch(t, ic.Contents.BuildRepositories, []string{"secret repository", "other_secret repository"})
	require.ElementsMatch(t, ic.Contents.RuntimeRepositories, []string{"repository"})
	require.ElementsMatch(t, ic.Contents.Keyring, []string{"key"})
	require.ElementsMatch(t, ic.Contents.Packages, []string{"package", "other_package"})
}

func TestUserContents(t *testing.T) {
	ctx := context.Background()

	configPath := filepath.Join("testdata", "users.apko.yaml")
	hasher := sha256.New()
	ic := types.ImageConfiguration{}

	require.NoError(t, ic.Load(ctx, configPath, []string{}, hasher))
	if err := ic.Validate(); err != nil {
		t.Fatal(err)
	}

	require.Equal(t, "/not/home", ic.Accounts.Users[0].HomeDir)
	require.Equal(t, "/home/user", ic.Accounts.Users[1].HomeDir)
}

func TestMergeInto(t *testing.T) {
	tests := []struct {
		name     string
		source   types.ImageConfiguration
		target   types.ImageConfiguration
		expected types.ImageConfiguration
	}{{
		name: "simple blend of contents",
		source: types.ImageConfiguration{
			Contents: types.ImageContents{
				Keyring:             []string{"foo"},
				BuildRepositories:   []string{"foo"},
				RuntimeRepositories: []string{"foo"},
				Packages:            []string{"foo"},
			},
			Environment: map[string]string{
				"EXTRA": "foo",
				"VAR":   "foo",
			},
			Annotations: map[string]string{
				"org.extra": "foo",
				"org.blah":  "foo",
			},
			Volumes: []string{
				"volume1",
			},
		},
		target: types.ImageConfiguration{
			Contents: types.ImageContents{
				Keyring:             []string{"bar"},
				BuildRepositories:   []string{"bar"},
				RuntimeRepositories: []string{"bar"},
				Packages:            []string{"bar"},
			},
		},
		expected: types.ImageConfiguration{
			Contents: types.ImageContents{
				Keyring:             []string{"foo", "bar"},
				BuildRepositories:   []string{"foo", "bar"},
				RuntimeRepositories: []string{"foo", "bar"},
				Packages:            []string{"foo", "bar"},
			},
			Environment: map[string]string{
				"EXTRA": "foo",
				"VAR":   "foo",
			},
			Annotations: map[string]string{
				"org.extra": "foo",
				"org.blah":  "foo",
			},
			Volumes: []string{
				"volume1",
			},
		},
	}, {
		name: "simple blend of contents",
		source: types.ImageConfiguration{
			Contents: types.ImageContents{
				Keyring:             []string{"foo"},
				BuildRepositories:   []string{"foo"},
				RuntimeRepositories: []string{"foo"},
				Packages:            []string{"foo"},
			},
		},
		target: types.ImageConfiguration{
			Contents: types.ImageContents{
				Keyring:             []string{"bar"},
				BuildRepositories:   []string{"bar"},
				RuntimeRepositories: []string{"bar"},
				Packages:            []string{"bar"},
			},
		},
		expected: types.ImageConfiguration{
			Contents: types.ImageContents{
				Keyring:             []string{"foo", "bar"},
				BuildRepositories:   []string{"foo", "bar"},
				RuntimeRepositories: []string{"foo", "bar"},
				Packages:            []string{"foo", "bar"},
			},
		},
	}, {
		name: "conflict resolution",
		source: types.ImageConfiguration{
			Contents: types.ImageContents{
				Keyring:             []string{"foo"},
				BuildRepositories:   []string{"foo"},
				RuntimeRepositories: []string{"foo"},
				Packages:            []string{"foo"},
			},
			Cmd:        "foo",
			StopSignal: "foo",
			WorkDir:    "foo",
			Accounts: types.ImageAccounts{
				RunAs: "foo",
				Users: []types.User{{
					UserName: "foo",
					UID:      1000,
					GID:      gid1000T,
					HomeDir:  "/home/foo",
				}},
			},
			Environment: map[string]string{
				"EXTRA": "foo",
				"VAR":   "foo",
			},
			Annotations: map[string]string{
				"org.extra": "foo",
				"org.blah":  "foo",
			},
		},
		target: types.ImageConfiguration{
			Cmd:        "bar",
			StopSignal: "bar",
			WorkDir:    "bar",
			Accounts: types.ImageAccounts{
				RunAs: "bar",
				Users: []types.User{{
					UserName: "bar",
					UID:      1001,
					GID:      gid1001T,
					HomeDir:  "/home/bar",
				}},
			},
			Environment: map[string]string{
				"VAR": "bar",
			},
			Annotations: map[string]string{
				"org.blah": "bar",
			},
		},
		expected: types.ImageConfiguration{
			Contents: types.ImageContents{
				Keyring:             []string{"foo"},
				BuildRepositories:   []string{"foo"},
				RuntimeRepositories: []string{"foo"},
				Packages:            []string{"foo"},
			},
			Cmd:        "bar",
			StopSignal: "bar",
			WorkDir:    "bar",
			Accounts: types.ImageAccounts{
				RunAs: "bar",
				Users: []types.User{{
					UserName: "foo",
					UID:      1000,
					GID:      gid1000T,
					HomeDir:  "/home/foo",
				}, {
					UserName: "bar",
					UID:      1001,
					GID:      gid1001T,
					HomeDir:  "/home/bar",
				}},
			},
			Environment: map[string]string{
				"EXTRA": "foo",
				"VAR":   "bar",
			},
			Annotations: map[string]string{
				"org.extra": "foo",
				"org.blah":  "bar",
			},
		},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.source.MergeInto(&tt.target)
			require.NoError(t, err)
			require.Equal(t, tt.expected, tt.target)
		})
	}
}

var (
	id0     = uint32(0)
	id0T    = types.GID(&id0)
	id1234  = uint32(1234)
	id1235  = uint32(1235)
	id1235T = types.GID(&id1235)
)

// Ensure unmarshalling YAML into an ImageConfuiguration
// does not result in unexpected GID=0
func Test_YAMLUnmarshalling_UID_GID_mapping(t *testing.T) {
	for _, test := range []struct {
		desc        string
		expectedUID uint32
		expectedGID types.GID
		rawYAML     string
	}{
		{
			desc:        "Unique GID gets propogated",
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
		var ic types.ImageConfiguration
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
