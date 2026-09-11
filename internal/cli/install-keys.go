package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/chainguard-dev/clog"
	"github.com/spf13/cobra"

	"chainguard.dev/apko/pkg/apk/apk"
)

func installKeys() *cobra.Command {
	return &cobra.Command{
		Use:     "install-keys",
		Example: `apko install-keys`,
		Short:   "Discover and install keys for all repositories",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			log := clog.FromContext(ctx)

			a, err := apk.New(ctx)
			if err != nil {
				return err
			}
			repos, err := a.GetRepositories()
			if err != nil {
				return err
			}
			for _, repo := range repos {
				keys, err := a.DiscoverKeys(ctx, repo)
				if err != nil {
					return err
				}

				if err := os.MkdirAll("/etc/apk/keys", 0755); err != nil {
					return err
				}
				for _, key := range keys {
					fn := filepath.Join("/etc/apk/keys", key.ID)
					if err := os.WriteFile(fn, key.Bytes, 0o644); err != nil { //nolint: gosec
						return fmt.Errorf("failed to write key %s: %w", key.ID, err)
					}
					log.With("repo", repo).Infof("wrote %s", fn)
				}
			}
			return nil
		},
	}
}
