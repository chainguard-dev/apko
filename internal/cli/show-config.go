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

package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"chainguard.dev/apko/pkg/apk/apk"
	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/build"
)

func showConfig() *cobra.Command {
	var extraKeys []string
	var extraBuildRepos []string
	var extraRepos []string
	var cacheDir string
	var offline bool

	cmd := &cobra.Command{
		Use:   "show-config",
		Short: "Show the configuration derived from loading a YAML file",
		Long: `Show the configuration derived from loading a YAML file.

The derived configuration is rendered in YAML.
`,
		Example: `  apko show-config <config.yaml>`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return ShowConfigCmd(cmd.Context(),
				build.WithConfig(args[0], []string{}),
				build.WithExtraKeys(extraKeys),
				build.WithExtraBuildRepos(extraBuildRepos),
				build.WithExtraRepos(extraRepos),
				build.WithCache(cacheDir, offline, apk.NewCache(true)),
			)
		},
	}

	cmd.Flags().StringSliceVarP(&extraKeys, "keyring-append", "k", []string{}, "path to extra keys to include in the keyring")
	cmd.Flags().StringSliceVarP(&extraBuildRepos, "build-repository-append", "b", []string{}, "path to extra repositories to include")
	cmd.Flags().StringSliceVarP(&extraRepos, "repository-append", "r", []string{}, "path to extra repositories to include")
	cmd.Flags().StringVar(&cacheDir, "cache-dir", "", "directory to use for caching apk packages and indexes (default '' means to use system-defined cache directory)")
	cmd.Flags().BoolVar(&offline, "offline", false, "do not use network to fetch packages (cache must be pre-populated)")

	return cmd
}

func ShowConfigCmd(ctx context.Context, opts ...build.Option) error {
	wd, err := os.MkdirTemp("", "apko-*")
	if err != nil {
		return fmt.Errorf("failed to create working directory: %w", err)
	}
	defer os.RemoveAll(wd)

	fs := apkfs.DirFS(ctx, wd, apkfs.WithCreateDir())

	bc, err := build.New(ctx, fs, opts...)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)

	if err := enc.Encode(bc.ImageConfiguration()); err != nil {
		return fmt.Errorf("failed to encode YAML document: %w", err)
	}

	if _, err := buf.WriteTo(os.Stdout); err != nil {
		return fmt.Errorf("failed to write YAML document: %w", err)
	}

	return nil
}
