package types_test

import (
	"context"
	"crypto/sha256"
	"path/filepath"
	"testing"

	"chainguard.dev/apko/pkg/build/types"
	"github.com/stretchr/testify/require"
)

func TestOverlayWithEmptyContents(t *testing.T) {
	ctx := context.Background()

	config_path := filepath.Join("testdata", "overlay", "overlay.apko.yaml")
	hasher := sha256.New()
	ic := types.ImageConfiguration{}

	require.NoError(t, ic.Load(ctx, config_path, hasher))
	require.ElementsMatch(t, ic.Contents.Repositories, []string{"repository"})
	require.ElementsMatch(t, ic.Contents.Keyring, []string{"key"})
	require.ElementsMatch(t, ic.Contents.Packages, []string{"package"})
}

func TestOverlayWithAdditionalPackages(t *testing.T) {
	ctx := context.Background()

	config_path := filepath.Join("testdata", "overlay", "overlay_with_package.apko.yaml")
	hasher := sha256.New()
	ic := types.ImageConfiguration{}

	require.NoError(t, ic.Load(ctx, config_path, hasher))
	require.ElementsMatch(t, ic.Contents.Repositories, []string{"repository"})
	require.ElementsMatch(t, ic.Contents.Keyring, []string{"key"})
	require.ElementsMatch(t, ic.Contents.Packages, []string{"package", "other_package"})
}
