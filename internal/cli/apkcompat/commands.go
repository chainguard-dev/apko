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

package apkcompat

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/chainguard-dev/clog/slag"
	charmlog "github.com/charmbracelet/log"
	"github.com/spf13/cobra"
	"sigs.k8s.io/release-utils/version"
)

// GlobalOptions holds global flags that apply to all commands
type GlobalOptions struct {
	Root             string
	Arch             string
	Repository       []string
	KeysDir          string
	CacheDir         string
	CacheMaxAge      int
	Quiet            bool
	Verbose          int
	AllowUntrusted   bool
	NoNetwork        bool
	NoCache          bool
	NoProgress       bool
	Progress         bool
	Interactive      bool
	Wait             int
	RepositoriesFile string
	UpdateCache      bool
	ForceRefresh     bool
}

var globalOpts = &GlobalOptions{}

func New() *cobra.Command {
	level := slag.Level(slog.LevelInfo)

	cmd := &cobra.Command{
		Use:               "apko-as-apk",
		Short:             "APK-compatible package manager using apko",
		DisableAutoGenTag: true,
		SilenceUsage:      true,
		SilenceErrors:     true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			http.DefaultTransport = userAgentTransport{http.DefaultTransport}

			// Adjust log level based on verbose/quiet flags
			if globalOpts.Quiet {
				level = slag.Level(slog.LevelError)
			} else if globalOpts.Verbose > 0 {
				if globalOpts.Verbose == 1 {
					level = slag.Level(slog.LevelDebug)
				} else {
					level = slag.Level(slog.LevelDebug - 1)
				}
			}

			slog.SetDefault(slog.New(charmlog.NewWithOptions(os.Stderr, charmlog.Options{
				ReportTimestamp: true,
				Level:           charmlog.Level(level),
			})))

			return nil
		},
	}

	// Global options matching apk command line flags
	cmd.PersistentFlags().StringVarP(&globalOpts.Root, "root", "p", "/", "Manage file system at ROOT")
	cmd.PersistentFlags().StringVar(&globalOpts.Arch, "arch", "", "Temporarily override architecture")
	cmd.PersistentFlags().StringSliceVarP(&globalOpts.Repository, "repository", "X", nil, "Specify additional package repository")
	cmd.PersistentFlags().StringVar(&globalOpts.KeysDir, "keys-dir", "", "Override directory of trusted keys")
	cmd.PersistentFlags().StringVar(&globalOpts.CacheDir, "cache-dir", "", "Temporarily override the cache directory")
	cmd.PersistentFlags().IntVar(&globalOpts.CacheMaxAge, "cache-max-age", 4*60, "Maximum AGE (in minutes) for index in cache before it's refreshed")
	cmd.PersistentFlags().BoolVarP(&globalOpts.Quiet, "quiet", "q", false, "Print less information")
	cmd.PersistentFlags().CountVarP(&globalOpts.Verbose, "verbose", "v", "Print more information (can be specified twice)")
	cmd.PersistentFlags().BoolVar(&globalOpts.AllowUntrusted, "allow-untrusted", false, "Install packages with untrusted signature or no signature")
	cmd.PersistentFlags().BoolVar(&globalOpts.NoNetwork, "no-network", false, "Do not use the network")
	cmd.PersistentFlags().BoolVar(&globalOpts.NoCache, "no-cache", false, "Do not use any local cache path")
	cmd.PersistentFlags().BoolVar(&globalOpts.NoProgress, "no-progress", false, "Disable progress bar even for TTYs")
	cmd.PersistentFlags().BoolVar(&globalOpts.Progress, "progress", false, "Show progress")
	cmd.PersistentFlags().BoolVarP(&globalOpts.Interactive, "interactive", "i", false, "Ask confirmation before performing certain operations")
	cmd.PersistentFlags().IntVar(&globalOpts.Wait, "wait", 0, "Wait for TIME seconds to get an exclusive repository lock before failing")
	cmd.PersistentFlags().StringVar(&globalOpts.RepositoriesFile, "repositories-file", "", "Override system repositories file")
	cmd.PersistentFlags().BoolVarP(&globalOpts.UpdateCache, "update-cache", "U", false, "Alias for '--cache-max-age 0'")
	cmd.PersistentFlags().BoolVar(&globalOpts.ForceRefresh, "force-refresh", false, "Do not use cached files (local or from proxy)")

	// Add subcommands
	cmd.AddCommand(addCmd())
	cmd.AddCommand(updateCmd())
	cmd.AddCommand(infoCmd())
	cmd.AddCommand(version.Version())

	return cmd
}

type userAgentTransport struct{ t http.RoundTripper }

func (u userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", fmt.Sprintf("apko-as-apk/%s", version.GetVersionInfo().GitVersion))
	return u.t.RoundTrip(req)
}
