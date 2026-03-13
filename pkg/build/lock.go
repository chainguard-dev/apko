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

package build

import (
	"context"
	"fmt"
	"maps"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/apko/pkg/build/types"
	pkglock "chainguard.dev/apko/pkg/lock"
)

// LockImageConfiguration returns a map of locked image configurations for each architecture,
// plus an entry for the "index" pseudo-architecture that represents the intersection of packages
// across all the real architecture configs. It also returns a map of missing packages for each
// architecture that could not be locked. Using the "index" architecture is equivalent to what
// this used to return prior to supporting per-arch locked configs.
func LockImageConfiguration(ctx context.Context, ic types.ImageConfiguration, opts ...Option) (map[string]*types.ImageConfiguration, map[string][]string, error) {
	ics, missing, _, err := LockImageConfigurationWithPackages(ctx, ic, opts...)
	return ics, missing, err
}

// LockImageConfigurationWithPackages is like LockImageConfiguration but additionally returns
// the resolved package metadata per architecture. The returned map contains the full
// RepositoryPackage objects as resolved by the solver.
// When a lockfile is used, the resolved packages map will be nil as the full package metadata
// is not available from lockfiles.
func LockImageConfigurationWithPackages(ctx context.Context, ic types.ImageConfiguration, opts ...Option) (map[string]*types.ImageConfiguration, map[string][]string, map[types.Architecture][]*apk.RepositoryPackage, error) {
	o, input, err := NewOptions(append(opts, WithImageConfiguration(ic))...)
	if err != nil {
		return nil, nil, nil, err
	}

	input.Contents.BuildRepositories = sets.List(sets.New(input.Contents.BuildRepositories...).Insert(o.ExtraBuildRepos...))
	input.Contents.Repositories = sets.List(sets.New(input.Contents.Repositories...).Insert(o.ExtraRepos...))
	input.Contents.Keyring = sets.List(sets.New(input.Contents.Keyring...).Insert(o.ExtraKeyFiles...))

	mc, err := NewMultiArch(ctx, input.Archs, append(opts, WithImageConfiguration(*input))...)
	if err != nil {
		return nil, nil, nil, err
	}

	// Determine the exact versions of our transitive packages and lock them
	// down in the "resolved" configuration, so that this build may be
	// reproduced exactly.
	var pls map[string][]string
	var resolvedPkgs map[types.Architecture][]*apk.RepositoryPackage
	missing := map[string][]string{}
	if o.Lockfile == "" {
		archs, pkgs, err := resolvePackageList(ctx, mc)
		if err != nil {
			return nil, nil, nil, err
		}
		resolvedPkgs = pkgs
		pls, missing, err = unify(input.Contents.Packages, archs)
		if err != nil {
			return nil, missing, nil, err
		}
	} else {
		l, err := pkglock.FromFile(o.Lockfile)
		if err != nil {
			return nil, nil, nil, err
		}
		for _, bc := range mc.Contexts {
			if err := bc.VerifyLockfileConsistency(ctx, l.Config); err != nil {
				return nil, nil, nil, err
			}
		}
		pls = l.Arch2LockedPackages(input.Archs)
	}

	ics := make(map[string]*types.ImageConfiguration, len(mc.Contexts)+1)
	// Set the locked package lists.
	for arch, pl := range pls {
		// Create a defensive copy of "input".
		copied := types.ImageConfiguration{}
		if err := input.MergeInto(&copied); err != nil {
			return nil, nil, nil, err
		}

		copied.Contents.Packages = pl

		if arch != "index" {
			// Overwrite single-arch configs with their specific arch.
			copied.Archs = []types.Architecture{types.ParseArchitecture(arch)}
		}

		ics[arch] = &copied
	}

	return ics, missing, resolvedPkgs, nil
}

func resolvePackageList(ctx context.Context, mc *MultiArch) ([]resolved, map[types.Architecture][]*apk.RepositoryPackage, error) {
	archs := make([]resolved, 0, len(mc.Contexts))

	toInstalls, err := mc.BuildPackageLists(ctx)
	if err != nil {
		return nil, nil, err
	}
	for arch, pkgs := range toInstalls {
		r := resolved{
			// ParseArchitecture normalizes the architecture into the
			// canonical OCI form (amd64, not x86_64)
			arch:     types.ParseArchitecture(arch.ToAPK()).String(),
			packages: make(sets.Set[string], len(pkgs)),
			versions: make(map[string]string, len(pkgs)),
			provided: make(map[string]sets.Set[string], len(pkgs)),
		}
		for _, pkg := range pkgs {
			r.packages.Insert(pkg.Name)
			r.versions[pkg.Name] = pkg.Version

			for _, prov := range pkg.Provides {
				parts := packageNameRegex.FindAllStringSubmatch(prov, -1)
				if len(parts) == 0 || len(parts[0]) < 2 {
					continue
				}
				ps, ok := r.provided[pkg.Name]
				if !ok {
					ps = sets.New[string]()
				}
				ps.Insert(parts[0][1])
				r.provided[pkg.Name] = ps
			}
		}
		archs = append(archs, r)
	}
	return archs, toInstalls, nil
}

type resolved struct {
	arch     string
	packages sets.Set[string]
	versions map[string]string
	pinned   map[string]string
	provided map[string]sets.Set[string]
}

// unify returns (locked packages (per arch), missing packages (per arch), error)
func unify(originals []string, inputs []resolved) (map[string][]string, map[string][]string, error) {
	if len(originals) == 0 || len(inputs) == 0 {
		// If there are no original packages, then we can't really do anything.
		// This used to return nil but multi-arch unification assumes we always
		// have an "index" entry, even if it's empty, so we return this now.
		// Mostly this is to satisfy some tests that have no package inputs.
		return map[string][]string{"index": {}}, nil, nil
	}
	originalPackages := resolved{
		packages: make(sets.Set[string], len(originals)),
		versions: make(map[string]string, len(originals)),
		pinned:   make(map[string]string, len(originals)),
	}

	byArch := map[string][]string{}

	for _, orig := range originals {
		name := orig
		version := ""
		pinned := ""

		// The function we want from go-apk is private, but these are all the
		// special characters that delimit the package name from the constraint
		// so lop off the package name and stick the rest of the constraint into
		// the versions map.
		if idx := strings.IndexAny(orig, "=<>~"); idx >= 0 {
			name = orig[:idx]
			version = orig[idx:]
		}

		// Extract pinned version if present
		if idx := strings.IndexAny(orig, "@"); idx >= 0 {
			pinned = orig[idx:]
		}

		// Remove pinned suffix from name and version
		name = strings.TrimSuffix(name, pinned)
		version = strings.TrimSuffix(version, pinned)

		originalPackages.packages.Insert(name)
		originalPackages.versions[name] = version
		originalPackages.pinned[name] = pinned
	}

	// Start accumulating using the first entry, and unify it with the other
	// architectures.
	acc := resolved{
		packages: inputs[0].packages.Clone(),
		versions: maps.Clone(inputs[0].versions),
		provided: inputs[0].provided,
	}
	for _, next := range inputs[1:] {
		if reflect.DeepEqual(acc.versions, next.versions) && reflect.DeepEqual(acc.provided, next.provided) {
			// If the package set's versions and provided packages match, then we're done.
			continue
		}

		// Remove any packages from our unification that do not appear in this
		// architecture's locked set.
		if diff := acc.packages.Difference(next.packages); diff.Len() > 0 {
			acc.packages.Delete(diff.UnsortedList()...)
		}
		// Walk through each of the packages remaining in our unification, and
		// remove any where this architecture disagrees with the unification.
		for _, pkg := range acc.packages.UnsortedList() {
			// When we find a package that has resolved differently, remove
			// it from our unified locked set.
			if acc.versions[pkg] != next.versions[pkg] {
				acc.packages.Delete(pkg)
				delete(acc.versions, pkg)
				delete(acc.provided, pkg)
			}
			if !acc.provided[pkg].Equal(next.provided[pkg]) {
				// If the package provides different things across architectures
				// then narrow what it provides to the common subset.
				acc.provided[pkg] = acc.provided[pkg].Intersection(next.provided[pkg])
			}
		}
	}

	// Compute the set of original packages that are missing from our locked
	// configuration, and turn them into errors.
	missing := originalPackages.packages.Difference(acc.packages)
	if missing.Len() > 0 {
		for _, provider := range acc.provided {
			if provider == nil {
				// Doesn't provide anything
				continue
			}
			if provider.HasAny(missing.UnsortedList()...) {
				// This package provides some of the "missing" packages, so they
				// are not really missing.  Remove them from the "missing" set,
				// and elide the warning.
				missing = missing.Difference(provider)
			}
		}
		// There are still things missing even factoring in "provided" packages.
		if missing.Len() > 0 {
			m := make(map[string][]string, len(missing))
			for _, pkg := range sets.List(missing) {
				s := make(map[string]sets.Set[string], 2)
				for _, in := range inputs {
					set, ok := s[in.versions[pkg]]
					if !ok {
						set = sets.New[string]()
					}
					set.Insert(in.arch)
					s[in.versions[pkg]] = set
				}
				versionClusters := make([]string, 0, len(s))
				for k, v := range s {
					versionClusters = append(versionClusters, fmt.Sprintf("%s (%s)", k, strings.Join(sets.List(v), ", ")))
				}
				sort.Strings(versionClusters)
				m[pkg] = versionClusters
			}
			return nil, nil, fmt.Errorf("unable to lock packages to a consistent version: %v", m)
		}
	}

	// Allocate a list sufficient for holding all of our locked package versions
	// as well as the packages we were unable to lock.
	allPl := make([]string, 0, len(acc.versions)+missing.Len())

	// Append any missing packages with their original constraints coming in.
	// NOTE: the originalPackages "versions" includes the remainder of the
	// package constraint including the operator.
	for _, pkg := range sets.List(missing) {
		if ver := originalPackages.versions[pkg]; ver != "" {
			if pin := originalPackages.versions[pkg]; pin != "" {
				allPl = append(allPl, fmt.Sprintf("%s%s%s", pkg, ver, pin))
			} else {
				allPl = append(allPl, fmt.Sprintf("%s%s", pkg, ver))
			}
		} else {
			allPl = append(allPl, pkg)
		}
	}

	allPl = slices.Concat(setPkgNames(acc, originalPackages), allPl)

	// Sort the package list explicitly with the `=` included.
	// This is because (foo, foo-bar) sorts differently than (foo=1, foo-bar=1)
	// due to the presence or absence of the `=` character.
	sort.Strings(allPl)

	// "index" is a sentinel value for the intersectino of all architectures.
	// This is a reference to the OCI image index we'll be producing with it.
	byArch["index"] = allPl

	for _, input := range inputs {
		pl := setPkgNames(input, originalPackages)

		// Sort the package list explicitly with the `=` included.
		// This is because (foo, foo-bar) sorts differently than (foo=1, foo-bar=1)
		// due to the presence or absence of the `=` character.
		sort.Strings(pl)
		byArch[input.arch] = pl
	}

	// If a particular architecture is missing additional packages from the
	// locked set that it produced, than warn about those as well.
	missingByArch := make(map[string][]string, len(inputs))
	for _, input := range inputs {
		missingHere := input.packages.Difference(acc.packages).Difference(missing)
		if missingHere.Len() > 0 {
			missingByArch[input.arch] = sets.List(missingHere)
		}
	}
	if len(missingByArch) > 0 {
		return byArch, missingByArch, nil
	}

	return byArch, nil, nil
}

// setPkgNames returns a list of package names with their versions and pins
func setPkgNames(input resolved, original resolved) []string {
	pl := make([]string, 0, len(input.packages))

	// Append all the resolved and unified packages with an exact match based on the
	// resolved version we found.
	for _, pkg := range sets.List(input.packages) {
		pkgName := fmt.Sprintf("%s=%s", pkg, input.versions[pkg])
		if pin := original.pinned[pkg]; pin != "" {
			pkgName = fmt.Sprintf("%s%s", pkgName, pin)
		}

		// If the package provides something (such as a meta package) that has been
		// specified with a pin, then we populate the pin based on what it provides.
		for _, prov := range input.provided[pkg].UnsortedList() {
			if strings.IndexAny(prov, ":") >= 0 {
				continue
			}
			if pin := original.pinned[prov]; pin != "" {
				pkgName = fmt.Sprintf("%s%s", pkgName, pin)
				break
			}
		}

		pl = append(pl, pkgName)
	}
	return pl
}

// Copied from go-apk's version.go
var packageNameRegex = regexp.MustCompile(`^([^@=><~]+)(([=><~]+)([^@]+))?(@([a-zA-Z0-9]+))?$`)
