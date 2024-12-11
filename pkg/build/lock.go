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
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"

	"chainguard.dev/apko/pkg/build/types"
)

// LockImageConfiguration returns a map of locked image configurations for each architecture,
// plus an entry for the "index" pseudo-architecture that represents the intersection of packages
// across all the real architecture configs. It also returns a map of missing packages for each
// architecture that could not be locked. Using the "index" architecture is equivalent to what
// this used to return prior to supporting per-arch locked configs.
func LockImageConfiguration(ctx context.Context, ic types.ImageConfiguration, opts ...Option) (map[string]*types.ImageConfiguration, map[string][]string, error) {
	mc, err := NewMultiArch(ctx, ic.Archs, append(opts, WithImageConfiguration(ic))...)
	if err != nil {
		return nil, nil, err
	}

	archs := make([]resolved, 0, len(ic.Archs))
	ics := make(map[string]*types.ImageConfiguration, len(ic.Archs)+1)

	// Determine the exact versions of our transitive packages and lock them
	// down in the "resolved" configuration, so that this build may be
	// reproduced exactly.
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

	pls, missing, err := unify(ic.Contents.Packages, archs)
	if err != nil {
		return nil, missing, err
	}

	// Set the locked package lists.
	for arch, pl := range pls {
		// Create a defensive copy of "ic".
		copied := types.ImageConfiguration{}
		if err := ic.MergeInto(&copied); err != nil {
			return nil, nil, err
		}

		copied.Contents.Packages = pl

		if arch != "index" {
			// Overwrite single-arch configs with their specific arch.
			copied.Archs = []types.Architecture{types.ParseArchitecture(arch)}
		}

		ics[arch] = &copied
	}

	return ics, missing, nil
}

type resolved struct {
	arch     string
	packages sets.Set[string]
	versions map[string]string
	provided map[string]sets.Set[string]
}

// unify returns (locked packages (per arch), missing packages (per arch), error)
func unify(originals []string, inputs []resolved) (map[string][]string, map[string][]string, error) {
	if len(originals) == 0 {
		// If there are no original packages, then we can't really do anything.
		// This used to return nil but multi-arch unification assumes we always
		// have an "index" entry, even if it's empty, so we return this now.
		// Mostly this is to satisfy some tests that have no package inputs.
		return map[string][]string{"index": {}}, nil, nil
	}
	originalPackages := resolved{
		packages: make(sets.Set[string], len(originals)),
		versions: make(map[string]string, len(originals)),
	}

	byArch := map[string][]string{}

	for _, orig := range originals {
		name := orig
		// The function we want from go-apk is private, but these are all the
		// special characters that delimit the package name from the cosntraint
		// so lop off the package name and stick the rest of the constraint into
		// the versions map.
		if idx := strings.IndexAny(orig, "=<>~"); idx >= 0 {
			name = orig[:idx]
		}
		originalPackages.packages.Insert(name)
		originalPackages.versions[name] = strings.TrimPrefix(orig, name)
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
	pl := make([]string, 0, len(acc.versions)+missing.Len())

	// Append any missing packages with their original constraints coming in.
	// NOTE: the originalPackages "versions" includes the remainder of the
	// package constraint including the operator.
	for _, pkg := range sets.List(missing) {
		if ver := originalPackages.versions[pkg]; ver != "" {
			pl = append(pl, fmt.Sprintf("%s%s", pkg, ver))
		} else {
			pl = append(pl, pkg)
		}
	}

	// Append all of the resolved and unified packages with an exact match
	// based on the resolved version we found.
	for _, pkg := range sets.List(acc.packages) {
		pl = append(pl, fmt.Sprintf("%s=%s", pkg, acc.versions[pkg]))
	}

	// "index" is a sentinel value for the intersectino of all architectures.
	// This is a reference to the OCI image index we'll be producing with it.
	byArch["index"] = pl

	for _, input := range inputs {
		pl := make([]string, 0, len(input.packages))
		for _, pkg := range sets.List(input.packages) {
			pl = append(pl, fmt.Sprintf("%s=%s", pkg, input.versions[pkg]))
		}
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

// Copied from go-apk's version.go
var packageNameRegex = regexp.MustCompile(`^([^@=><~]+)(([=><~]+)([^@]+))?(@([a-zA-Z0-9]+))?$`)
