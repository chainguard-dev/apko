package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/apko/pkg/apk/apk/keyring"
)

func installKeys() *cobra.Command {
	return &cobra.Command{
		Use:     "install-keys",
		Example: `apko install-keys`,
		Short:   "Discover and install keys for all repositories",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			a, err := apk.New(ctx)
			if err != nil {
				return err
			}
			repos, err := a.GetRepositories()
			if err != nil {
				return err
			}

			keyRing, err := keyring.NewKeyRing(
				keyring.AddRepositories(repos...),
			)
			if err != nil {
				return fmt.Errorf("creating keyring: %w", err)
			}

			return a.DownloadAndStoreKeys(ctx, keyRing)
		},
	}
}
