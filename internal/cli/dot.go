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
	"slices"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"github.com/pkg/browser"
	"github.com/spf13/cobra"
	"github.com/tmc/dot"
	"golang.org/x/sync/errgroup"

	"github.com/chainguard-dev/clog"

	"chainguard.dev/apko/pkg/apk/apk"
	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/build/types"
)

var extRegistryViewer string

func dotcmd() *cobra.Command {
	var extraKeys []string
	var extraBuildRepos []string
	var extraRepos []string
	var archstrs []string
	var web, span bool
	var cacheDir string
	var offline bool

	cmd := &cobra.Command{
		Use:   "dot",
		Short: "Output a digraph showing the resolved dependencies of an apko config",
		Long: `Output a digraph showing the resolved dependencies of an apko config

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
	cmd.Flags().StringSliceVar(&archstrs, "arch", nil, "architectures to build for (e.g., x86_64,ppc64le,arm64) -- default is all, unless specified in config. Can also use 'host' to indicate arch of host this is running on")
	cmd.Flags().BoolVarP(&span, "spanning-tree", "S", false, "does something like a spanning tree to avoid a huge number of edges")
	cmd.Flags().BoolVar(&web, "web", false, "launch a browser")
	cmd.Flags().StringVar(&cacheDir, "cache-dir", "", "directory to use for caching apk packages and indexes (default '' means to use system-defined cache directory)")
	cmd.Flags().BoolVar(&offline, "offline", false, "do not use network to fetch packages (cache must be pre-populated)")
	cmd.Flags().StringVarP(&extRegistryViewer, "registry-explorer", "e", "apk.dag.dev", "FQDN of the registry explorer that rendered nodes in SVG will link to.")

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
	fs := apkfs.DirFS(ctx, wd, apkfs.WithCreateDir())
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
		addedNodes := map[string]*dot.Node{}

		out := dot.NewGraph("images")
		if err := out.Set("rankdir", "LR"); err != nil {
			panic(err)
		}
		if err := out.SetType(dot.DIGRAPH); err != nil {
			panic(err)
		}

		// Helper function to add an edge with a tooltip describing both nodes and dependency type
		addEdgeWithTooltip := func(from, to *dot.Node, fromName, toName, depType string) error {
			edge := dot.NewEdge(from, to)

			if web {
				tooltip := fmt.Sprintf("%s → %s", fromName, toName)
				if depType != "" {
					tooltip += fmt.Sprintf(" (%s)", depType)
				}

				if err := edge.Set("tooltip", tooltip); err != nil {
					return err
				}
			}

			_, err := out.AddEdge(edge)
			return err
		}

		file := dot.NewNode(configFile)
		if _, err := out.AddNode(file); err != nil {
			panic(err)
		}

		for _, pkg := range ic.Contents.Packages {
			var n *dot.Node
			if existing, ok := addedNodes[pkg]; ok {
				n = existing
			} else {
				n = dot.NewNode(pkg)
				addedNodes[pkg] = n
				if _, err := out.AddNode(n); err != nil {
					panic(err)
				}
			}

			if err := addEdgeWithTooltip(file, n, configFile, pkg, "required"); err != nil {
				panic(err)
			}
			if before, _, ok := strings.Cut(pkg, "="); ok {
				var p *dot.Node
				if existing, ok := addedNodes[before]; ok {
					p = existing
				} else {
					p = dot.NewNode(before)
					addedNodes[before] = p
					if _, err := out.AddNode(p); err != nil {
						panic(err)
					}
				}
				if err := addEdgeWithTooltip(n, p, pkg, before, "exact version"); err != nil {
					panic(err)
				}

				// Set URL on the constraint node to point to the same package
				if web {
					if targetPkg, ok := pkgMap[before]; ok {
						url := extURL(targetPkg)
						if err := n.Set("URL", url); err != nil {
							panic(err)
						}
						if err := n.Set("target", "_blank"); err != nil {
							panic(err)
						}
						if err := n.Set("tooltip", targetPkg.Description); err != nil {
							panic(err)
						}
					}
				}

				deps[before] = struct{}{}
			} else if before, _, ok := strings.Cut(pkg, "~"); ok {
				var p *dot.Node
				if existing, ok := addedNodes[before]; ok {
					p = existing
				} else {
					p = dot.NewNode(before)
					addedNodes[before] = p
					if _, err := out.AddNode(p); err != nil {
						panic(err)
					}
				}
				if err := addEdgeWithTooltip(n, p, pkg, before, "compatible version"); err != nil {
					panic(err)
				}

				// Set URL on the constraint node to point to the same package
				if web {
					if targetPkg, ok := pkgMap[before]; ok {
						url := extURL(targetPkg)
						if err := n.Set("URL", url); err != nil {
							panic(err)
						}
						if err := n.Set("target", "_blank"); err != nil {
							panic(err)
						}
						if err := n.Set("tooltip", targetPkg.Description); err != nil {
							panic(err)
						}
					}
				}

				deps[before] = struct{}{}
			} else {
				deps[pkg] = struct{}{}
			}
		}

		renderDeps := func(pkg *apk.RepositoryPackage) {
			var n *dot.Node
			if existing, ok := addedNodes[pkg.Name]; ok {
				// Node already exists, use it
				n = existing
			} else {
				// Create new node
				n = dot.NewNode(pkg.Name)
				addedNodes[pkg.Name] = n
				if _, err := out.AddNode(n); err != nil && !errors.Is(err, dot.ErrDuplicateNode) {
					panic(err)
				}
			}

			if err := n.Set("label", pkgver(pkg)); err != nil {
				panic(err)
			}
			if err := n.Set("tooltip", pkg.Description); err != nil {
				panic(err)
			}
			if web {
				url := extURL(pkg)
				if err := n.Set("URL", url); err != nil {
					panic(err)
				}
				if err := n.Set("target", "_blank"); err != nil {
					panic(err)
				}
			}

			for _, dep := range dmap[pkg.Name] {
				if before, _, ok := strings.Cut(dep, "="); ok {
					dep = before
				} else if before, _, ok := strings.Cut(dep, "~"); ok {
					dep = before
				}

				var d *dot.Node
				if existing, ok := addedNodes[dep]; ok {
					d = existing
				} else {
					d = dot.NewNode(dep)
					addedNodes[dep] = d
					if _, err := out.AddNode(d); err != nil && !errors.Is(err, dot.ErrDuplicateNode) {
						panic(err)
					}
				}

				if web {
					if !strings.Contains(dep, ":") {
						if depPkg, ok := pkgMap[dep]; ok {
							if err := d.Set("URL", extURL(depPkg)); err != nil {
								panic(err)
							}
							if err := d.Set("target", "_blank"); err != nil {
								panic(err)
							}
							if err := d.Set("tooltip", depPkg.Description); err != nil {
								panic(err)
							}
						} else {
							// Don't set a URL for dependencies not in the package map (e.g., virtual dependencies, provides).
							// Setting a local link would cause a panic when clicked since the package doesn't exist.
							log.Debugf("Dependency %s not in package map, skipping URL", dep)
						}
					}
				}
				if _, ok := edges[dep]; !ok || !span {
					// This check is stupid but otherwise cycles render dumb.
					if pkg.Name != dep {
						if err := addEdgeWithTooltip(n, d, pkg.Name, dep, "dependency"); err != nil {
							panic(err)
						}
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
			var n *dot.Node
			if existing, ok := addedNodes[pkg.Name]; ok {
				n = existing
			} else {
				n = dot.NewNode(pkg.Name)
				addedNodes[pkg.Name] = n
				if _, err := out.AddNode(n); err != nil && !errors.Is(err, dot.ErrDuplicateNode) {
					panic(err)
				}
			}
			if err := n.Set("label", pkgver(pkg)); err != nil {
				panic(err)
			}
			if pkg.Description != "" {
				if err := n.Set("tooltip", pkg.Description); err != nil {
					panic(err)
				}
			} else {
				log.Debugf("No description for package %s", pkg.Name)
			}

			for _, prov := range pmap[pkg.Name] {
				if _, ok := deps[prov]; !ok {
					if before, _, ok := strings.Cut(prov, "="); ok {
						if _, ok := deps[before]; ok {
							var p *dot.Node
							if existing, ok := addedNodes[before]; ok {
								p = existing
							} else {
								p = dot.NewNode(before)
								addedNodes[before] = p
								if _, err := out.AddNode(p); err != nil && !errors.Is(err, dot.ErrDuplicateNode) {
									panic(err)
								}
							}
							if err := p.Set("shape", "rect"); err != nil {
								panic(err)
							}

							if err := addEdgeWithTooltip(p, n, before, pkg.Name, "provides"); err != nil {
								panic(err)
							}
						}
						continue
					} else if before, _, ok := strings.Cut(prov, "~"); ok {
						if _, ok := deps[before]; ok {
							var p *dot.Node
							if existing, ok := addedNodes[before]; ok {
								p = existing
							} else {
								p = dot.NewNode(before)
								addedNodes[before] = p
								if _, err := out.AddNode(p); err != nil && !errors.Is(err, dot.ErrDuplicateNode) {
									panic(err)
								}
							}
							if err := p.Set("shape", "rect"); err != nil {
								panic(err)
							}

							if err := addEdgeWithTooltip(p, n, before, pkg.Name, "provides"); err != nil {
								panic(err)
							}
						}
						continue
					} else {
						continue
					}
				}
				var p *dot.Node
				if existing, ok := addedNodes[prov]; ok {
					p = existing
				} else {
					p = dot.NewNode(prov)
					addedNodes[prov] = p
					if _, err := out.AddNode(p); err != nil && !errors.Is(err, dot.ErrDuplicateNode) {
						panic(err)
					}
				}
				if _, ok := edges[pkg.Name]; !ok || !span {
					if err := addEdgeWithTooltip(p, n, prov, pkg.Name, "provides"); err != nil {
						panic(err)
					}
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

			if _, err := out.AddNode(errorNode); err != nil {
				panic(err)
			}
			walkErrors(out, resolveErr, errorNode)
		}

		return out
	}

	if web {
		log.Infof("Prefixing node links with registry-explorer: %s", extRegistryViewer)
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

			var svgBuf strings.Builder
			cmd.Stdout = &svgBuf

			if err := cmd.Run(); err != nil {
				fmt.Fprintf(w, "error rendering %v: %v", nodes, err)
				return
			}

			// Post-process SVG to remove the graph-level tooltip
			svg := svgBuf.String()
			// Remove the constant "images" tooltip from the SVG
			svg = strings.ReplaceAll(svg, `<title>images</title>`, "")

			if _, err := w.Write([]byte(svg)); err != nil {
				log.Errorf("error writing SVG response: %v", err)
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
			return browser.OpenURL(fmt.Sprintf("http://localhost:%d", l.Addr().(*net.TCPAddr).Port))
		})

		g.Go(func() error {
			<-ctx.Done()
			server.Close()
			return ctx.Err()
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

func extURL(pkg *apk.RepositoryPackage) string {
	// Get the package URL like: https://packages.wolfi.dev/repo/arch/package-version.apk
	pkgURL := pkg.URL()

	// Replace protocol :// with /
	pkgURL = strings.ReplaceAll(pkgURL, "://", "/")

	// Replace any remaining : with /
	pkgURL = strings.ReplaceAll(pkgURL, ":", "/")

	// Normalize multiple consecutive slashes to single slash
	for strings.Contains(pkgURL, "//") {
		pkgURL = strings.ReplaceAll(pkgURL, "//", "/")
	}

	// Build the final chaindag URL
	result := fmt.Sprintf("https://%s/%s", extRegistryViewer, pkgURL)
	log.Debugf("Package %s -> URL: %s", pkg.Name, result)
	return result
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
	if _, err := out.AddNode(node); err != nil {
		panic(err)
	}
	edge := dot.NewEdge(parent, node)
	if label != "" {
		if err := edge.Set("label", label); err != nil {
			panic(err)
		}
	}
	if _, err := out.AddEdge(edge); err != nil {
		panic(err)
	}

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
