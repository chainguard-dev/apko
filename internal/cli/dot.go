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
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	apkfs "github.com/chainguard-dev/go-apk/pkg/fs"
	"github.com/skratchdot/open-golang/open"
	"github.com/spf13/cobra"
	"github.com/tmc/dot"
	"gitlab.alpinelinux.org/alpine/go/repository"
	"golang.org/x/exp/slices"
	"golang.org/x/sync/errgroup"

	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/build/types"
)

func dotcmd() *cobra.Command {
	var extraKeys []string
	var extraRepos []string
	var archstrs []string
	var web, span bool

	cmd := &cobra.Command{
		Use:   "dot",
		Short: "Output a digraph showing the resolved dependencies of an apko config.",
		Long: `Output a digraph showing the resolved dependencies of an apko config.

# Render an svg of example.yaml
apko dot example.yaml | dot -Tvsg > graph.svg

# Open browser to explore example.yaml
apko dot --web example.yaml

# Open browser to explore example.yaml, rendering a (almost) minimum spanning tree
apko dot --web -S example.yaml
`,
		Example: `  apko show-packages <config.yaml>`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			archs := types.ParseArchitectures(archstrs)
			return DotCmd(cmd.Context(), args[0], archs, web, span,
				build.WithConfig(args[0]),
				build.WithExtraKeys(extraKeys),
				build.WithExtraRepos(extraRepos),
			)
		},
	}

	cmd.Flags().StringSliceVarP(&extraKeys, "keyring-append", "k", []string{}, "path to extra keys to include in the keyring")
	cmd.Flags().StringSliceVarP(&extraRepos, "repository-append", "r", []string{}, "path to extra repositories to include")
	cmd.Flags().StringSliceVar(&archstrs, "arch", nil, "architectures to build for (e.g., x86_64,ppc64le,arm64) -- default is all, unless specified in config. Can also use 'host' to indicate arch of host this is running on")
	cmd.Flags().BoolVarP(&span, "spanning-tree", "S", false, "does something like a spanning tree to avoid a huge number of edges")
	cmd.Flags().BoolVar(&web, "web", false, "launch a browser")

	return cmd
}

func DotCmd(ctx context.Context, configFile string, archs []types.Architecture, web, span bool, opts ...build.Option) error {
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
	o.Logger().Infof("Determining packages for %d architectures: %+v", len(ic.Archs), ic.Archs)

	// The build context options is sometimes copied in the next functions. Ensure
	// we have the directory defined and created by invoking the function early.
	defer os.RemoveAll(o.TempDir())

	// TODO: Perhaps we want to support multiple architectures?
	arch := archs[0]

	// working directory for this architecture
	wd = filepath.Join(wd, arch.ToAPK())
	bopts := slices.Clone(opts)
	bopts = append(bopts, build.WithArch(arch))
	fs := apkfs.DirFS(wd, apkfs.WithCreateDir())
	bc, err := build.New(ctx, fs, bopts...)
	if err != nil {
		return err
	}
	bc.Logger().Infof("using working directory %s", wd)

	pkgs, _, err := bc.BuildPackageList(ctx)
	if err != nil {
		return fmt.Errorf("failed to get package list for image: %w", err)
	}

	dmap := map[string][]string{}
	pmap := map[string][]string{}
	pkgMap := map[string]*repository.RepositoryPackage{}

	for _, pkg := range pkgs {
		dmap[pkg.Name] = pkg.Dependencies
		pmap[pkg.Name] = pkg.Provides
		pkgMap[pkg.Name] = pkg
	}

	args := []string{}

	render := func(args []string) *dot.Graph {
		edges := map[string]struct{}{}
		deps := map[string]struct{}{}

		out := dot.NewGraph("images")
		if err := out.Set("rankdir", "LR"); err != nil {
			panic(err)
		}
		out.SetType(dot.DIGRAPH)

		file := dot.NewNode(configFile)
		out.AddNode(file)

		for _, pkg := range ic.Contents.Packages {
			n := dot.NewNode(pkg)
			out.AddNode(n)
			out.AddEdge(dot.NewEdge(file, n))
			deps[pkg] = struct{}{}
		}

		renderDeps := func(pkg *repository.RepositoryPackage) {
			n := dot.NewNode(pkg.Name)
			if err := n.Set("label", pkgver(pkg)); err != nil {
				panic(err)
			}
			if web {
				if err := n.Set("URL", link(args, pkg.Name)); err != nil {
					panic(err)
				}
			}
			out.AddNode(n)

			for _, dep := range dmap[pkg.Name] {
				d := dot.NewNode(dep)
				if web {
					if !strings.Contains(dep, ":") {
						if err := d.Set("URL", link(args, dep)); err != nil {
							panic(err)
						}
					}
				}
				out.AddNode(d)
				if _, ok := edges[dep]; !ok || !span {
					// This check is stupid but otherwise cycles render dumb.
					if pkg.Name != dep {
						out.AddEdge(dot.NewEdge(n, d))
						edges[dep] = struct{}{}
					}
				}
				deps[dep] = struct{}{}
			}
		}

		done := map[string]struct{}{}
		for _, arg := range args {
			pkg, ok := pkgMap[arg]
			if !ok {
				panic(fmt.Errorf("package not found: %q", arg))
			}
			renderDeps(pkg)
			done[arg] = struct{}{}
		}

		for _, pkg := range pkgs {
			if _, ok := done[pkg.Name]; ok {
				continue
			}
			renderDeps(pkg)
		}

		renderProvs := func(pkg *repository.RepositoryPackage) {
			n := dot.NewNode(pkg.Name)
			if err := n.Set("label", pkgver(pkg)); err != nil {
				panic(err)
			}
			out.AddNode(n)

			for _, prov := range pmap[pkg.Name] {
				if _, ok := deps[prov]; !ok {
					if before, _, ok := strings.Cut(prov, "="); ok {
						if _, ok := deps[before]; ok {
							p := dot.NewNode(before)
							if err := p.Set("shape", "rect"); err != nil {
								panic(err)
							}
							out.AddNode(p)

							out.AddEdge(dot.NewEdge(p, n))
						}
						continue
					} else {
						continue
					}
				}
				p := dot.NewNode(prov)
				out.AddNode(p)
				if _, ok := edges[pkg.Name]; !ok || !span {
					out.AddEdge(dot.NewEdge(p, n))
					edges[pkg.Name] = struct{}{}
				}
			}
		}

		done = map[string]struct{}{}
		for _, arg := range args {
			pkg, ok := pkgMap[arg]
			if !ok {
				panic(fmt.Errorf("package not found: %q", arg))
			}
			renderProvs(pkg)
			done[arg] = struct{}{}
		}

		for _, pkg := range pkgs {
			if _, ok := done[pkg.Name]; ok {
				continue
			}
			renderProvs(pkg)
		}

		return out
	}

	if web {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				return
			}
			nodes := r.URL.Query()["node"]

			if len(nodes) == 0 {
				nodes = args
			}

			out := render(nodes)

			log.Printf("%s: rendering %v", r.URL, nodes)
			cmd := exec.Command("dot", "-Tsvg")
			cmd.Stdin = strings.NewReader(out.String())
			cmd.Stdout = w

			if err := cmd.Run(); err != nil {
				fmt.Fprintf(w, "error rendering %v: %v", nodes, err)
				log.Fatal(err)
			}
		})

		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return err
		}

		server := &http.Server{
			Addr:              l.Addr().String(),
			ReadHeaderTimeout: 3 * time.Second,
		}

		log.Printf("%s", l.Addr().String())

		var g errgroup.Group
		g.Go(func() error {
			return server.Serve(l)
		})

		g.Go(func() error {
			return open.Run(fmt.Sprintf("http://localhost:%d", l.Addr().(*net.TCPAddr).Port))
		})

		return g.Wait()
	}

	out := render(args)

	fmt.Println(out.String())
	return nil
}

func pkgver(pkg *repository.RepositoryPackage) string {
	return fmt.Sprintf("%s-%s", pkg.Name, pkg.Version)
}

func link(args []string, pkg string) string {
	filtered := []string{}
	for _, a := range args {
		if a != pkg {
			filtered = append(filtered, a)
		}
	}
	ret := "/?node=" + pkg
	if len(filtered) > 0 {
		ret += "&node=" + strings.Join(filtered, "&node=")
	}
	return ret
}
