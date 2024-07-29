package cli

import (
	"fmt"
	"net/http"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"chainguard.dev/apko/pkg/apk/auth"
	"chainguard.dev/apko/pkg/apk/client"
)

func discoverKeys() *cobra.Command {
	var install bool
	cmd := &cobra.Command{
		Use:     "discover-keys",
		Example: `wolfictl apk discover-keys https://<apk-host>/<path>`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			u := args[0]

			keys, err := client.DiscoverKeys(ctx, u, http.DefaultClient, auth.DefaultAuthenticators)
			if err != nil {
				return err
			}

			if install {
				if err := os.MkdirAll("/etc/apk/keys", 0755); err != nil {
					return err
				}
				for _, key := range keys {
					if err := os.WriteFile(fmt.Sprintf("/etc/apk/keys/%s.rsa.pub", key.ID), key.Bytes, 0o644); err != nil { //nolint: gosec
						return fmt.Errorf("failed to write key %s: %w", key.ID, err)
					}
				}
			} else {
				if err := yaml.NewEncoder(os.Stdout).Encode(keys); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&install, "install", "i", false, "install the discovered keys")
	return cmd
}
