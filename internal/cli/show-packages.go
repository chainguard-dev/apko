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
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"text/template"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"github.com/chainguard-dev/clog"
	"github.com/spf13/cobra"
	"golang.org/x/exp/slices"

	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/build/types"
)

const (
	formatNameSpaceVersion                 = `{{ .Name }} {{ .Version }}`
	formatNameSpaceVersionWithSource       = `{{ .Name }} {{ .Version }} {{ .Source }}`
	formatNameSpaceEqualsVersion           = `{{ .Name }}={{ .Version }}`
	formatNameSpaceEqualsVersionWithSource = `{{ .Name }}={{ .Version }} {{ .Source }}`
	formatNameBracketsVersion              = `{{ .Name }} ({{ .Version }})`
	formatNameBracketsVersionWithSource    = `{{ .Name }} ({{ .Version }}) {{ .Source }}`
	formatPkgLock                          = `- {{ .Name }}={{ .Version }}`
	formatPkgLockWithSource                = `- {{ .Name }}={{ .Version }} # {{ .Source }}`
	showPkgsFormatDefault                  = formatNameSpaceVersion
)

var (
	showPkgsFormats = map[string]string{
		"name-version":          formatNameSpaceVersion,
		"name-version-source":   formatNameSpaceVersionWithSource,
		"name=version":          formatNameSpaceEqualsVersion,
		"name=version-source":   formatNameSpaceEqualsVersionWithSource,
		"name-(version)":        formatNameBracketsVersion,
		"name-(version)-source": formatNameBracketsVersionWithSource,
		"packagelock":           formatPkgLock,
		"packagelock-source":    formatPkgLockWithSource,
	}
)

type pkgInfo struct {
	Name    string
	Version string
	Source  string
}

func showPackages() *cobra.Command {
	var extraKeys []string
	var extraRepos []string
	var archstrs []string
	var format string
	var tmpl string
	var cacheDir string
	var offline bool

	cmd := &cobra.Command{
		Use:   "show-packages",
		Short: "Show the packages and versions that would be installed by a configuration",
		Long: `Show the packages and versions that would be installed by a configuration.
The result is identical to the first stages of a build, but does not actuall install anything.

The output is one of several pre-defined formats, or can be customized to any go template, using
the provided vars. See https://pkg.go.dev/text/template for more information. Available vars are
.Name, .Version, .Source

The pre-defined formats are:
  name-version:          {{ .Name }} {{ .Version }}
  name-version-source:   {{ .Name }} {{ .Version }} {{ .Source }}
  name=version:          {{ .Name }}={{ .Version }}
  name=version-source:   {{ .Name }}={{ .Version }} {{ .Source }}
  name-(version):        {{ .Name }} ({{ .Version }})
  name-(version)-source: {{ .Name }} ({{ .Version }}) {{ .Source }}
  packagelock:               - {{ .Name }}={{ .Version }}
  packagelock-source:        - {{ .Name }}={{ .Version }} # {{ .Source }}

The default format is name-version.

packagelock and packagelock-source are particularly useful for inserting back into a yaml list of packages.
`,
		Example: `  apko show-packages <config.yaml>`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			archs := types.ParseArchitectures(archstrs)
			if t, ok := showPkgsFormats[format]; ok {
				tmpl = t
			} else {
				// assume it's a template
				tmpl = format
			}
			return ShowPackagesCmd(cmd.Context(), tmpl, archs,
				build.WithConfig(args[0]),
				build.WithExtraKeys(extraKeys),
				build.WithExtraRepos(extraRepos),
				build.WithCacheDir(cacheDir, offline),
			)
		},
	}

	cmd.Flags().StringSliceVarP(&extraKeys, "keyring-append", "k", []string{}, "path to extra keys to include in the keyring")
	cmd.Flags().StringSliceVarP(&extraRepos, "repository-append", "r", []string{}, "path to extra repositories to include")
	cmd.Flags().StringSliceVar(&archstrs, "arch", nil, "architectures to build for (e.g., x86_64,ppc64le,arm64) -- default is all, unless specified in config. Can also use 'host' to indicate arch of host this is running on")
	cmd.Flags().StringVar(&format, "format", showPkgsFormatDefault, "format for showing packages; if pre-defined from list, will use that, else go template. See https://pkg.go.dev/text/template for more information. Available vars are `.Name`, `.Version`, `.Source`")
	cmd.Flags().StringVar(&cacheDir, "cache-dir", "", "directory to use for caching apk packages and indexes (default '' means to use system-defined cache directory)")
	cmd.Flags().BoolVar(&offline, "offline", false, "do not use network to fetch packages (cache must be pre-populated)")

	return cmd
}

func ShowPackagesCmd(ctx context.Context, format string, archs []types.Architecture, opts ...build.Option) error {
	log := clog.FromContext(ctx)
	wd, err := os.MkdirTemp("", "apko-*")
	if err != nil {
		return fmt.Errorf("failed to create working directory: %w", err)
	}
	defer os.RemoveAll(wd)

	o, ic, err := build.NewOptions(opts...)
	if err != nil {
		return err
	}

	// cases:
	// - archs set: use those archs
	// - archs not set, bc.ImageConfiguration.Archs set: use Config archs
	// - archs not set, bc.ImageConfiguration.Archs not set: use all archs
	switch {
	case len(archs) != 0:
		ic.Archs = archs
	case len(ic.Archs) != 0:
		// do nothing
	default:
		ic.Archs = types.AllArchs
	}
	// save the final set we will build
	archs = ic.Archs
	log.Infof("Determining packages for %d architectures: %+v", len(ic.Archs), ic.Archs)

	// The build context options is sometimes copied in the next functions. Ensure
	// we have the directory defined and created by invoking the function early.
	defer os.RemoveAll(o.TempDir())

	tmpl, err := template.New("format").Parse(format)
	if err != nil {
		return fmt.Errorf("failed to parse format: %w", err)
	}

	for _, arch := range archs {
		arch := arch
		log := clog.New(slog.Default().Handler()).With("arch", arch.ToAPK())
		ctx = clog.WithLogger(ctx, log)

		// working directory for this architecture
		wd := filepath.Join(wd, arch.ToAPK())
		bopts := slices.Clone(opts)
		bopts = append(bopts, build.WithArch(arch))
		fs := apkfs.DirFS(wd, apkfs.WithCreateDir())
		bc, err := build.New(ctx, fs, bopts...)
		if err != nil {
			return err
		}
		log.Infof("using working directory %s", wd)

		pkgs, _, err := bc.BuildPackageList(ctx)
		if err != nil {
			return fmt.Errorf("failed to get package list for image: %w", err)
		}
		var p pkgInfo
		for _, pkg := range pkgs {
			p.Name = pkg.Name
			p.Version = pkg.Version
			p.Source = pkg.URL()
			if err = tmpl.Execute(os.Stdout, p); err != nil {
				return fmt.Errorf("failed to execute template: %w", err)
			}
			fmt.Println()
		}
	}
	return nil
}
