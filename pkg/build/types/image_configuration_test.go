package types_test

import (
	"context"
	"crypto/sha256"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/build/types"
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
