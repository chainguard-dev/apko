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
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/go-apk/pkg/apk"
	apkfs "github.com/chainguard-dev/go-apk/pkg/fs"
	"github.com/skratchdot/open-golang/open"
	"github.com/spf13/cobra"
	"github.com/tmc/dot"
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
	var cacheDir string
	var offline bool

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
		Example: `  apko dot <config.yaml>`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			archs := types.ParseArchitectures(archstrs)
			return DotCmd(cmd.Context(), args[0], archs, web, span,
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
	cmd.Flags().BoolVarP(&span, "spanning-tree", "S", false, "does something like a spanning tree to avoid a huge number of edges")
	cmd.Flags().BoolVar(&web, "web", false, "launch a browser")
	cmd.Flags().StringVar(&cacheDir, "cache-dir", "", "directory to use for caching apk packages and indexes (default '' means to use system-defined cache directory)")
	cmd.Flags().BoolVar(&offline, "offline", false, "do not use network to fetch packages (cache must be pre-populated)")

	return cmd
}

func DotCmd(ctx context.Context, configFile string, archs []types.Architecture, web, span bool, opts ...build.Option) error {
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
	log.Infof("using working directory %s", wd)

	pkgs, _, resolveErr := bc.BuildPackageList(ctx)
	if resolveErr != nil {
		log.Errorf("failed to get package list for image: %v", resolveErr)
	}

	dmap := map[string][]string{}
	pmap := map[string][]string{}
	pkgMap := map[string]*apk.RepositoryPackage{}

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
			if before, _, ok := strings.Cut(pkg, "~"); ok {
				p := dot.NewNode(before)
				out.AddNode(p)
				out.AddEdge(dot.NewEdge(n, p))

				deps[before] = struct{}{}
			} else {
				deps[pkg] = struct{}{}
			}
		}

		renderDeps := func(pkg *apk.RepositoryPackage) {
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
				if before, _, ok := strings.Cut(dep, "~"); ok {
					dep = before
				}
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

		renderProvs := func(pkg *apk.RepositoryPackage) {
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
					} else if before, _, ok := strings.Cut(prov, "~"); ok {
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

		if resolveErr != nil {
			errorNode := dot.NewNode("❌ error")

			out.AddNode(errorNode)
			walkErrors(out, resolveErr, errorNode)
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

			log.Infof("%s: rendering %v", r.URL, nodes)
			cmd := exec.Command("dot", "-Tsvg")
			cmd.Stdin = strings.NewReader(out.String())
			cmd.Stdout = w

			if err := cmd.Run(); err != nil {
				fmt.Fprintf(w, "error rendering %v: %v", nodes, err)
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

		log.Infof("%s", l.Addr().String())

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

func pkgver(pkg *apk.RepositoryPackage) string {
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

type unwrapper interface {
	Unwrap() error
}

type unwrappers interface {
	Unwrap() []error
}

func canUnwrap(err error) bool {
	if _, ok := err.(unwrapper); ok { //nolint:errorlint
		return true
	}

	if _, ok := err.(unwrappers); ok { //nolint:errorlint
		return true
	}

	return false
}

func makeNode(out *dot.Graph, err error, parent *dot.Node) *dot.Node {
	nodeName, label := errToNode(err)
	if nodeName == "" {
		if canUnwrap(err) {
			return parent
		}

		nodeName = "❌ " + err.Error()
	}

	node := dot.NewNode(nodeName)
	out.AddNode(node)
	edge := dot.NewEdge(parent, node)
	if label != "" {
		if err := edge.Set("label", label); err != nil {
			panic(err)
		}
	}
	out.AddEdge(edge)

	return node
}

func walkErrors(out *dot.Graph, err error, parent *dot.Node) {
	node := makeNode(out, err, parent)

	if wrapped := errors.Unwrap(err); wrapped != nil {
		walkErrors(out, wrapped, node)
	} else if mw, ok := err.(unwrappers); ok { //nolint:errorlint
		for _, wrapped := range mw.Unwrap() {
			walkErrors(out, wrapped, node)
		}
	}
}

func errToNode(err error) (string, string) {
	switch v := err.(type) { //nolint:errorlint
	case *apk.ConstraintError:
		return v.Constraint, "solving constraint"
	case *apk.DepError:
		return pkgver(v.Package), "resolving deps"
	case *apk.DisqualifiedError:
		return pkgver(v.Package), ""
	}

	return "", ""
}
