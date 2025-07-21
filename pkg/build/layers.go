// Copyright 2025 Chainguard, Inc.
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

package build

import (
	"archive/tar"
	"bytes"
	"cmp"
	"context"
	"fmt"
	"io"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"

	"chainguard.dev/apko/pkg/apk/apk"
	apkfs "chainguard.dev/apko/pkg/apk/fs"

	"github.com/chainguard-dev/clog"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func (bc *Context) buildLayers(ctx context.Context) ([]v1.Layer, error) {
	log := clog.FromContext(ctx)

	if strategy := bc.ic.Layering.Strategy; strategy != "origin" {
		return nil, fmt.Errorf("unrecognized layering strategy %q", strategy)
	}

	if bc.ic.Contents.BaseImage != nil {
		return nil, fmt.Errorf("layering with %q is unsupported", "baseimage")
	}

	// Build a single fs.FS, the normal way (this writes to bc.fs).
	diffs, err := bc.buildImage(ctx)
	if err != nil {
		return nil, fmt.Errorf("building filesystem: %w", err)
	}

	pkgs := make([]*apk.Package, 0, len(diffs))
	pkgToDiff := map[*apk.Package][]byte{}
	for _, pkgDiff := range diffs {
		pkgs = append(pkgs, pkgDiff.Package)
		pkgToDiff[pkgDiff.Package] = pkgDiff.Diff
	}

	// We don't pass around repositories cleanly between apko and the library
	// formerly known as go-apk. Instead, we write stuff to bc.fs directly
	// and the library formerly known as go-apk reads from bc.fs to know
	// which repositories it can fetch packages from. We need to call this
	// to overwrite etc/apk/repositories with _only_ runtime repositories
	// and not runtime + build repositories.
	//
	// TODO: Clean this up when time permits.
	if err := bc.postBuildSetApk(ctx); err != nil {
		return nil, err
	}

	// Use our layering strategy to partition packages into a set of Budget groups.
	groups, err := groupByOriginAndSize(pkgs, bc.ic.Layering.Budget)
	if err != nil {
		return nil, fmt.Errorf("grouping packages: %w", err)
	}
	log.Infof("Building %d layers with budget %d", len(groups), bc.ic.Layering.Budget)

	for i, g := range groups {
		log.Infof("  layer[%d]:", i)

		for _, pkg := range g.pkgs {
			log.Infof("    - %s=%s", pkg.Name, pkg.Version)
		}
	}

	// Then partition that single fs.FS into multiple layers based on our layering strategy.
	return splitLayers(ctx, bc.fs, groups, pkgToDiff, bc.o.TempDir())
}

func replacesGroup(rep string, g *group) (bool, error) {
	constraint := apk.ResolvePackageNameVersionPin(rep)

	// Look for the package to make sure the version satisfies Replaces.
	for _, pkg := range g.pkgs {
		if pkg.Name != constraint.Name {
			// This is not the package we're looking for.
			continue
		}

		ver, err := apk.ParseVersion(pkg.Version)
		if err != nil {
			return false, fmt.Errorf("parsing %s version %s: %w", pkg.Name, pkg.Version, err)
		}

		ok, err := constraint.SatisfiedBy(ver)
		if err != nil {
			return false, fmt.Errorf("checking %s satisfies %s: %w", pkg.Version, constraint.Name, err)
		}

		if ok {
			return true, nil
		}
	}

	return false, nil
}

func groupByOriginAndSize(pkgs []*apk.Package, budget int) ([]*group, error) {
	// First, we're going to group packages by their origin.
	byOrigin := map[string]*group{}
	for _, pkg := range pkgs {
		origin := pkg.Origin
		if _, ok := byOrigin[origin]; !ok {
			byOrigin[origin] = &group{}
		}

		g, ok := byOrigin[origin]
		if !ok {
			panic(fmt.Errorf("byOrigin[%q] missing", origin))
		}

		g.pkgs = append(g.pkgs, pkg)
	}

	// Then we need to merge any packages that replace each other.
	byPackage := map[string]*group{}
	for _, g := range byOrigin {
		for _, pkg := range g.pkgs {
			byPackage[pkg.Name] = g
		}
	}

	replaceMap := map[string][]string{}
	for _, g := range byPackage {
		for _, pkg := range g.pkgs {
			if len(pkg.Replaces) == 0 {
				continue
			}

			replaceMap[pkg.Name] = pkg.Replaces
		}
	}

	for pkg, replaces := range replaceMap {
		for _, rep := range replaces {
			constraint := apk.ResolvePackageNameVersionPin(rep)

			replacee, ok := byPackage[constraint.Name]
			if !ok {
				// Whatever this package replaces is not in the image, that's normal.
				continue
			}

			if ok, err := replacesGroup(rep, replacee); err != nil {
				return nil, fmt.Errorf("checking %s replaces %s: %w", pkg, constraint.Name, err)
			} else if !ok {
				continue
			}

			g, ok := byPackage[pkg]
			if !ok {
				panic(fmt.Errorf("byPackage[%q] missing", pkg))
			}

			// If they're already merged, nothing to do.
			if replacee == g {
				continue
			}

			// Otherwise, we need to merge the two groups.
			merged := merge(g, replacee)

			// Update our maps so we can test identity above.
			for _, pkg := range merged.pkgs {
				byPackage[pkg.Name] = merged
				byOrigin[pkg.Origin] = merged
			}
		}
	}

	// Now we need to pick the best groups to keep.
	// First pass we'll set the size of each group to the sum of the installed size of all its packages.
	groups := make([]*group, 0, budget)
	seen := map[*group]struct{}{}
	for v := range maps.Values(byOrigin) {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		groups = append(groups, v)
	}
	for _, g := range groups {
		for _, pkg := range g.pkgs {
			g.size += pkg.InstalledSize
			g.tiebreaker = max(g.tiebreaker, pkg.Name)
		}
	}

	// Then we'll sort by the size and take the top $budget, merging the remainders.
	slices.SortFunc(groups, func(a, b *group) int {
		return cmp.Or(
			cmp.Compare(b.size, a.size),             // Descending size.
			cmp.Compare(a.tiebreaker, b.tiebreaker)) // In the rare case where we have identical sizes.
	})

	if len(groups) > budget {
		cutoff := max(budget-1, 0) // Even if budget == 0, we want 1 group.

		remainder := groups[cutoff:]
		groups = groups[:cutoff]

		groups = append(groups, merge(remainder...))
	}

	// Sort packages too just so they're in a consistent order.
	for _, g := range groups {
		slices.SortFunc(g.pkgs, func(a, b *apk.Package) int {
			return cmp.Compare(a.Name, b.Name)
		})
	}

	return groups, nil
}

type group struct {
	pkgs []*apk.Package

	size uint64

	// This is silly but in the event that two groups have identical size,
	// we want a predictable sort order _somehow_.
	tiebreaker string
}

func merge(groups ...*group) *group {
	merged := &group{}
	for _, g := range groups {
		merged.pkgs = slices.Concat(merged.pkgs, g.pkgs)
		merged.size += g.size
		merged.tiebreaker = max(merged.tiebreaker, g.tiebreaker)
	}
	return merged
}

func splitLayers(ctx context.Context, fsys apkfs.FullFS, groups []*group, pkgToDiff map[*apk.Package][]byte, tmpdir string) ([]v1.Layer, error) {
	buf := make([]byte, 1<<20)

	// We'll create a writer for each layer and a map to quickly access the writer given a package or group.
	packageToWriter := map[string]*layerWriter{}
	groupToWriter := map[*group]*layerWriter{}

	for _, g := range groups {
		f, err := os.CreateTemp(tmpdir, "layer-*.tar.gz")
		if err != nil {
			return nil, err
		}
		defer f.Close()

		w := newLayerWriter(f)
		groupToWriter[g] = w

		for _, pkg := range g.pkgs {
			packageToWriter[pkg.Name] = w
		}
	}

	// The top layer holds anything that doesn't belong to a package.
	f, err := os.CreateTemp(tmpdir, "layer-*.tar.gz")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	top := newLayerWriter(f)

	// We want to match the file info from the top layer's idb file below,
	// so when we run into it, just stash it for later.
	var idb tar.Header

	// In a tar file, it is customary to include directories before files in those directories.
	// In order to know which directories we need to include, we maintain a directory stack for each layer.
	// We compare those stacks to the full FS that we're walking whenever we create a new tar entry.
	// If the main stack doesn't match the layer's stack, we update the layer's stack and add
	// any missing directory entries to the layer before we write the actual file entry.
	stack := []*file{}

	for f, err := range walkFS(ctx, fsys) {
		if err != nil {
			return nil, err
		}

		// Maintain our "main" stack.
		if f.header.Typeflag == tar.TypeDir {
			// Pop off any directories that are not parents of the current file's directory.
			for i := len(stack) - 1; i >= 0; i-- {
				if stack[i].path == path.Dir(f.path) {
					break
				}

				stack = stack[:i]
			}

			// Push the current file onto the stack.
			stack = append(stack, f)
		}

		// By default, all files go into the top layer.
		w := top

		// However, if a file implements an extension interface that tells us what package owns it,
		// we can use that to determine which layer it belongs to (if any).
		if pkger, ok := f.info.(interface {
			Package() *apk.Package
		}); ok {
			if pkg := pkger.Package(); pkg != nil {
				w, ok = packageToWriter[pkg.Name]
				if !ok {
					panic(fmt.Errorf("packageToWriter[%q] missing", pkg.Name))
				}
			}
		}

		// As described above, bring the layer's stack up to date with the main stack.
		for _, todo := range w.alignStacks(stack) {
			// We need to write any missing directories returned by alignStacks.
			// But sometimes the result of alignStacks will include the file we're
			// about to write (f) after this loop. In those cases, make sure we
			// don't write it twice by skipping over it here.
			if todo.header == f.header {
				continue
			}

			// This is a little weird, but bear with me...
			// Often, multiple packages (and thus layers) contain files in the same directory.
			// The directories in each package likely have different timestamps.
			// The overall image's filesystem will only have one directory entry, so there
			// will be a "winner" timestamp that actually ends up in the image.
			// Unfortunately, this means that we don't get great layer deduplication
			// in a lot of situations, and the timestamp of some directories in any given
			// layer are influenced by the timestamp of directories in _other_ layers.
			// Since timestamps almost never have an observable effect on the image behavior,
			// and the "real" timestamp will end up in the "top" layer anyway and overwrite
			// the directory metadata for these package-ful layers, we can improve deduplication
			// without having any real effect on the image by overwriting this directory's
			// timestamp with the timestamp of the "f" file we're about to write to this layer.
			todo.header.ModTime = f.header.ModTime

			if err := w.w.WriteHeader(todo.header); err != nil {
				return nil, fmt.Errorf("writing header %s: %w", todo.header.Name, err)
			}
		}

		// Now we're back to normal tar stuff.
		if err := w.w.WriteHeader(f.header); err != nil {
			return nil, fmt.Errorf("writing header %s: %w", f.header.Name, err)
		}

		if f.header.Typeflag == tar.TypeReg && f.header.Size > 0 {
			data, err := fsys.Open(f.path)
			if err != nil {
				return nil, fmt.Errorf("opening %s: %w", f.path, err)
			}

			if _, err := io.CopyBuffer(w.w, data, buf); err != nil {
				return nil, fmt.Errorf("copying %s: %w", f.path, err)
			}

			// Should never fail in practice.
			if err := data.Close(); err != nil {
				return nil, fmt.Errorf("closing %s: %w", f.path, err)
			}
		}

		if f.header.Name == "usr/lib/apk/db/installed" {
			idb = *f.header
		}
	}

	// Once we're done walking the FS, we need to finalize each layer...
	layers := make([]v1.Layer, 0, len(groups)+1)
	for i, g := range groups {
		w := groupToWriter[g]

		// Add a partial installed db to satisfy scanners.
		{
			var buf bytes.Buffer
			for _, pkg := range g.pkgs {
				if _, err := buf.Write(pkgToDiff[pkg]); err != nil {
					return nil, err
				}
			}

			// Ensure parent directory exists in the tar.
			if err := w.w.WriteHeader(&tar.Header{
				Name:     path.Dir(idb.Name),
				Typeflag: tar.TypeDir,
				Mode:     idb.Mode,
				ModTime:  idb.ModTime,
			}); err != nil {
				return nil, fmt.Errorf("writing header for usr/lib/apk/db/: %w", err)
			}

			// Only the size should be different across layers.
			idb.Size = int64(buf.Len())

			if err := w.w.WriteHeader(&idb); err != nil {
				return nil, err
			}

			if _, err := io.Copy(w.w, &buf); err != nil {
				return nil, err
			}
		}

		l, err := w.finalize()
		if err != nil {
			return nil, fmt.Errorf("finalizing group[%d] layer: %w", i, err)
		}
		layers = append(layers, l)
	}

	// ...including the top layer.
	topLayer, err := top.finalize()
	if err != nil {
		return nil, fmt.Errorf("finalizing top layer: %w", err)
	}

	layers = append(layers, topLayer)

	return layers, nil
}

// alignStacks ensures that w.stack is aligned with the passed in "main" stack
// by updating w.stack and returning any directories w hasn't already seen written.
// This relies on the fact that WalkDir iterates in lexicographic order, so we will
// only ever write a tar entry the first time we see a dir (for a given layer).
//
// Examples...
//
// stack:   [etc]
// w.stack: []
// return:  [etc]
//
// stack:   [usr, usr/lib]
// w.stack: [etc, etc/apk, etc/apk/keys]
// return:  [usr, usr/lib]
//
// stack:   [usr, usr/lib]
// w.stack: [usr]
// return:  [usr/lib]
//
// stack:   [usr, usr/lib]
// w.stack: [usr, usr/bin]
// return:  [usr/lib]

// stack:   [usr, usr/lib]
// w.stack: [usr, usr/lib, usr/lib/foo]
// return:  []
func (w *layerWriter) alignStacks(stack []*file) []*file {
	for i := 0; i < max(len(w.stack), len(stack)); i++ {
		// The layer's stack is taller than the main stack, truncate layer's stack.
		if i >= len(stack) {
			w.stack = w.stack[:i]
			return nil
		}

		// Otherwise skip over any entries that are the same.
		if i < len(w.stack) && w.stack[i] == stack[i] {
			continue
		}

		// For anything left that's not the same, we'll truncate w.stack,
		// then append the main stack and return the difference.
		w.stack = w.stack[:i]
		w.stack = append(w.stack, stack[i:]...)
		return w.stack[i:]
	}

	return nil
}
