package types_test

import (
	"context"
	"crypto/sha256"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

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
	require.ElementsMatch(t, ic.Contents.RuntimeRepositories, []string{"runtime repository"})
	require.ElementsMatch(t, ic.Contents.Repositories, []string{"repository"})
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
	require.ElementsMatch(t, ic.Contents.RuntimeRepositories, []string{"runtime repository", "other runtime repository"})
	require.ElementsMatch(t, ic.Contents.Repositories, []string{"repository"})
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

	// Ensure this does not cause panic when users[1].gid is empty (defaulting to 0)
	ic.Summarize(ctx)
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
				Keyring:           []string{"foo"},
				BuildRepositories: []string{"foo"},
				Repositories:      []string{"foo"},
				Packages:          []string{"foo"},
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
				Keyring:           []string{"bar"},
				BuildRepositories: []string{"bar"},
				Repositories:      []string{"bar"},
				Packages:          []string{"bar"},
			},
		},
		expected: types.ImageConfiguration{
			Contents: types.ImageContents{
				Keyring:           []string{"foo", "bar"},
				BuildRepositories: []string{"foo", "bar"},
				Repositories:      []string{"foo", "bar"},
				Packages:          []string{"foo", "bar"},
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
				Keyring:           []string{"foo"},
				BuildRepositories: []string{"foo"},
				Repositories:      []string{"foo"},
				Packages:          []string{"foo"},
			},
		},
		target: types.ImageConfiguration{
			Contents: types.ImageContents{
				Keyring:           []string{"bar"},
				BuildRepositories: []string{"bar"},
				Repositories:      []string{"bar"},
				Packages:          []string{"bar"},
			},
		},
		expected: types.ImageConfiguration{
			Contents: types.ImageContents{
				Keyring:           []string{"foo", "bar"},
				BuildRepositories: []string{"foo", "bar"},
				Repositories:      []string{"foo", "bar"},
				Packages:          []string{"foo", "bar"},
			},
		},
	}, {
		name: "conflict resolution",
		source: types.ImageConfiguration{
			Contents: types.ImageContents{
				Keyring:           []string{"foo"},
				BuildRepositories: []string{"foo"},
				Repositories:      []string{"foo"},
				Packages:          []string{"foo"},
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
				Keyring:           []string{"foo"},
				BuildRepositories: []string{"foo"},
				Repositories:      []string{"foo"},
				Packages:          []string{"foo"},
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
