// Copyright 2026 Chainguard, Inc.
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

package apk

import (
	"fmt"
	"math/rand/v2"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const filterTestRepo = "https://example.com/repo/x86_64"

func filterTestIndex(pkgs []*Package) NamedIndex {
	repo := &Repository{URI: filterTestRepo}
	return NewNamedRepositoryWithIndex("", repo.WithIndex(&APKIndex{Packages: pkgs}))
}

func pkgKey(pkg *Package) string {
	return pkg.Name + "-" + pkg.Version
}

// resolveForTest resolves world and renders the result so that resolutions
// from different resolvers over the same *Package values compare equal.
func resolveForTest(t *testing.T, r *PkgResolver, world []string) ([]string, []string, error) {
	t.Helper()
	pkgs, conflicts, err := r.GetPackagesWithDependencies(t.Context(), world, nil)
	if err != nil {
		return nil, nil, err
	}
	got := make([]string, 0, len(pkgs))
	for _, pkg := range pkgs {
		got = append(got, fmt.Sprintf("%s %x %s", pkgKey(pkg.Package), pkg.Checksum, pkg.URL()))
	}
	return got, conflicts, nil
}

// requireSameResolution checks that a resolver filtered down to keep resolves
// world exactly as a resolver built from only the kept packages does.
func requireSameResolution(t *testing.T, all []*Package, keep func(*Package) bool, world []string) ([]string, error) {
	t.Helper()
	var subset []*Package
	for _, pkg := range all {
		if keep(pkg) {
			subset = append(subset, pkg)
		}
	}

	ctx := t.Context()
	filtered := BuildPkgResolver(ctx, []NamedIndex{filterTestIndex(all)}).Filtered(func(rp *RepositoryPackage) bool {
		return keep(rp.Package)
	})
	built := BuildPkgResolver(ctx, []NamedIndex{filterTestIndex(subset)})

	gotFiltered, conflictsFiltered, errFiltered := resolveForTest(t, filtered, world)
	gotBuilt, conflictsBuilt, errBuilt := resolveForTest(t, built, world)
	if errBuilt != nil {
		require.Errorf(t, errFiltered, "subset resolver failed with %v but filtered resolver succeeded with %v", errBuilt, gotFiltered)
		return nil, errBuilt
	}
	require.NoErrorf(t, errFiltered, "subset resolver gave %v", gotBuilt)
	// Install-if additions follow map iteration order even for a single
	// resolver, so only the set of packages is comparable.
	require.ElementsMatch(t, gotBuilt, gotFiltered)
	require.ElementsMatch(t, conflictsBuilt, conflictsFiltered)
	return gotBuilt, nil
}

func TestFilteredResolverMatchesSubset(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pkgs    []*Package
		hidden  []string // name-version of the packages the filter rejects
		world   []string
		want    []string // name-version, in install order
		wantErr bool
	}{{
		name: "highest version hidden",
		pkgs: []*Package{
			{Name: "foo", Version: "1.0-r0"},
			{Name: "foo", Version: "2.0-r0"},
		},
		hidden: []string{"foo-2.0-r0"},
		world:  []string{"foo"},
		want:   []string{"foo-1.0-r0"},
	}, {
		name: "only version hidden",
		pkgs: []*Package{
			{Name: "foo", Version: "1.0-r0"},
		},
		hidden:  []string{"foo-1.0-r0"},
		world:   []string{"foo"},
		wantErr: true,
	}, {
		name: "dependency only provided by a hidden package",
		pkgs: []*Package{
			{Name: "app", Version: "1-r0", Dependencies: []string{"so:libx.so.1"}},
			{Name: "libx", Version: "1-r0", Provides: []string{"so:libx.so.1=1"}},
		},
		hidden:  []string{"libx-1-r0"},
		world:   []string{"app"},
		wantErr: true,
	}, {
		name: "better provider hidden",
		pkgs: []*Package{
			{Name: "app", Version: "1-r0", Dependencies: []string{"cmd:x"}},
			{Name: "x-old", Version: "1-r0", Provides: []string{"cmd:x=1"}},
			{Name: "x-new", Version: "1-r0", Provides: []string{"cmd:x=2"}},
		},
		hidden: []string{"x-new-1-r0"},
		world:  []string{"app"},
		want:   []string{"x-old-1-r0", "app-1-r0"},
	}, {
		name: "versioned provide constraint skips hidden provider",
		pkgs: []*Package{
			{Name: "app", Version: "1-r0", Dependencies: []string{"so:libq.so.1>=1.1"}},
			{Name: "libq-a", Version: "1-r0", Provides: []string{"so:libq.so.1=1.2"}},
			{Name: "libq-b", Version: "1-r0", Provides: []string{"so:libq.so.1=1.3"}},
			{Name: "libq-c", Version: "1-r0", Provides: []string{"so:libq.so.1=1.0"}},
		},
		hidden: []string{"libq-b-1-r0"},
		world:  []string{"app"},
		want:   []string{"libq-a-1-r0", "app-1-r0"},
	}, {
		name: "install-if fires for visible packages",
		pkgs: []*Package{
			{Name: "app", Version: "1-r0", Dependencies: []string{"foo", "docs"}},
			{Name: "foo", Version: "1-r0"},
			{Name: "docs", Version: "1-r0"},
			{Name: "foo-doc", Version: "1-r0", InstallIf: []string{"foo", "docs"}},
		},
		world: []string{"app"},
		want:  []string{"docs-1-r0", "foo-1-r0", "foo-doc-1-r0", "app-1-r0"},
	}, {
		name: "install-if package hidden",
		pkgs: []*Package{
			{Name: "app", Version: "1-r0", Dependencies: []string{"foo", "docs"}},
			{Name: "foo", Version: "1-r0"},
			{Name: "docs", Version: "1-r0"},
			{Name: "foo-doc", Version: "1-r0", InstallIf: []string{"foo", "docs"}},
		},
		hidden: []string{"foo-doc-1-r0"},
		world:  []string{"app"},
		want:   []string{"docs-1-r0", "foo-1-r0", "app-1-r0"},
	}, {
		name: "install-if trigger hidden",
		pkgs: []*Package{
			{Name: "app", Version: "1-r0", Dependencies: []string{"foo", "docs"}},
			{Name: "foo", Version: "1-r0"},
			{Name: "docs", Version: "1-r0"},
			{Name: "docs-alt", Version: "1-r0", Provides: []string{"docs"}},
			{Name: "foo-doc", Version: "1-r0", InstallIf: []string{"foo", "docs"}},
		},
		hidden: []string{"docs-1-r0"},
		world:  []string{"app"},
		want:   []string{"docs-alt-1-r0", "foo-1-r0", "app-1-r0"},
	}, {
		name: "install-if on a versioned trigger with a hidden version",
		pkgs: []*Package{
			{Name: "app", Version: "1-r0", Dependencies: []string{"foo"}},
			{Name: "foo", Version: "1-r0"},
			{Name: "foo", Version: "2-r0"},
			{Name: "foo-extra", Version: "2-r0", InstallIf: []string{"foo=2-r0"}},
		},
		hidden: []string{"foo-2-r0"},
		world:  []string{"app"},
		want:   []string{"foo-1-r0", "app-1-r0"},
	}, {
		name: "install-if on a versioned trigger",
		pkgs: []*Package{
			{Name: "app", Version: "1-r0", Dependencies: []string{"foo"}},
			{Name: "foo", Version: "1-r0"},
			{Name: "foo", Version: "2-r0"},
			{Name: "foo-extra", Version: "2-r0", InstallIf: []string{"foo=2-r0"}},
		},
		world: []string{"app"},
		want:  []string{"foo-2-r0", "foo-extra-2-r0", "app-1-r0"},
	}, {
		name: "exact version pin on a hidden version",
		pkgs: []*Package{
			{Name: "foo", Version: "1.2-r0"},
			{Name: "foo", Version: "1.3-r0"},
		},
		hidden:  []string{"foo-1.2-r0"},
		world:   []string{"foo=1.2-r0"},
		wantErr: true,
	}, {
		name: "fuzzy version skips hidden",
		pkgs: []*Package{
			{Name: "foo", Version: "1.2-r0"},
			{Name: "foo", Version: "1.2.5-r0"},
			{Name: "foo", Version: "1.3-r0"},
		},
		hidden: []string{"foo-1.2.5-r0"},
		world:  []string{"foo~1.2"},
		want:   []string{"foo-1.2-r0"},
	}, {
		name: "greater-than skips hidden",
		pkgs: []*Package{
			{Name: "foo", Version: "1-r0"},
			{Name: "foo", Version: "2-r0"},
			{Name: "foo", Version: "3-r0"},
		},
		hidden: []string{"foo-3-r0"},
		world:  []string{"foo>1"},
		want:   []string{"foo-2-r0"},
	}, {
		name: "exclusion with a hidden alternative",
		pkgs: []*Package{
			{Name: "app", Version: "1-r0", Dependencies: []string{"!busybox", "sh"}},
			{Name: "busybox", Version: "1-r0", Provides: []string{"sh"}},
			{Name: "bash", Version: "1-r0", Provides: []string{"sh"}},
		},
		hidden:  []string{"bash-1-r0"},
		world:   []string{"app"},
		wantErr: true,
	}, {
		name: "exclusion with a visible alternative",
		pkgs: []*Package{
			{Name: "app", Version: "1-r0", Dependencies: []string{"!busybox", "sh"}},
			{Name: "busybox", Version: "1-r0", Provides: []string{"sh"}},
			{Name: "bash", Version: "1-r0", Provides: []string{"sh"}},
			{Name: "dash", Version: "1-r0", Provides: []string{"sh"}},
		},
		hidden: []string{"bash-1-r0"},
		world:  []string{"app"},
		want:   []string{"dash-1-r0", "app-1-r0"},
	}, {
		name: "conflicting provides between visible packages",
		pkgs: []*Package{
			{Name: "a", Version: "1-r0", Provides: []string{"x=1"}},
			{Name: "b", Version: "1-r0", Provides: []string{"x=2"}},
		},
		world:   []string{"a", "b"},
		wantErr: true,
	}, {
		name: "conflict resolved by hiding the conflicting provider",
		pkgs: []*Package{
			{Name: "app", Version: "1-r0", Dependencies: []string{"x"}},
			{Name: "a", Version: "1-r0", Provides: []string{"x=1"}},
			{Name: "b", Version: "1-r0", Provides: []string{"x=2"}},
		},
		hidden: []string{"b-1-r0"},
		world:  []string{"a", "app"},
		want:   []string{"a-1-r0", "app-1-r0"},
	}, {
		name: "constraint from a dependency skips hidden",
		pkgs: []*Package{
			{Name: "glibc", Version: "2.38-r10", Dependencies: []string{"so:ld-linux.so.1=1.0"}},
			{Name: "ld-linux", Version: "2.38-r10", Provides: []string{"so:ld-linux.so.1=1.0"}},
			{Name: "ld-linux", Version: "2.38-r11", Provides: []string{"so:ld-linux.so.1=1.1"}},
			{Name: "foo", Version: "1-r0", Dependencies: []string{"so:ld-linux.so.1"}},
		},
		hidden: []string{"ld-linux-2.38-r11"},
		world:  []string{"foo", "glibc"},
		want:   []string{"ld-linux-2.38-r10", "foo-1-r0", "glibc-2.38-r10"},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			hidden := map[string]bool{}
			for _, h := range tc.hidden {
				hidden[h] = true
			}
			keep := func(pkg *Package) bool { return !hidden[pkgKey(pkg)] }

			got, err := requireSameResolution(t, tc.pkgs, keep, tc.world)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			want := make([]string, 0, len(tc.want))
			for _, w := range tc.want {
				want = append(want, fmt.Sprintf("%s %x %s/%s.apk", w, []byte(nil), filterTestRepo, w))
			}
			require.Equal(t, want, got)
		})
	}
}

func loadTestIndex(t *testing.T, path string) []*Package {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	index, err := IndexFromArchive(f)
	require.NoError(t, err)
	return index.Packages
}

// TestFilteredResolverMatchesSubsetRandom checks filter equivalence over a
// real index, random package subsets and random worlds.
func TestFilteredResolverMatchesSubsetRandom(t *testing.T) {
	all := loadTestIndex(t, "testdata/alpine-317/APKINDEX.tar.gz")
	rng := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // deterministic test data

	var resolved, failed int
	for i := range 200 {
		fraction := 0.9 + 0.1*rng.Float64()
		members := make(map[*Package]bool, len(all))
		var visible []*Package
		for _, pkg := range all {
			if rng.Float64() < fraction {
				members[pkg] = true
				visible = append(visible, pkg)
			}
		}

		// Mostly ask for visible packages, sometimes for anything.
		world := make([]string, 0, 6)
		for range 1 + rng.IntN(6) {
			pool := visible
			if rng.IntN(10) == 0 {
				pool = all
			}
			world = append(world, pool[rng.IntN(len(pool))].Name)
		}
		slices.Sort(world)
		world = slices.Compact(world)

		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if _, err := requireSameResolution(t, all, func(pkg *Package) bool { return members[pkg] }, world); err != nil {
				failed++
			} else {
				resolved++
			}
		})
	}
	// Guard against a test that only ever compares two failures.
	require.Greater(t, resolved, 80, "resolved %d, failed %d", resolved, failed)
	require.Positive(t, failed)
}

func TestFilteredNilAndComposed(t *testing.T) {
	ctx := t.Context()
	pkgs := []*Package{
		{Name: "foo", Version: "1-r0"},
		{Name: "foo", Version: "2-r0"},
		{Name: "foo", Version: "3-r0"},
	}
	r := BuildPkgResolver(ctx, []NamedIndex{filterTestIndex(pkgs)})

	got, _, err := resolveForTest(t, r.Filtered(nil), []string{"foo"})
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Contains(t, got[0], "foo-3-r0 ")

	not := func(version string) PackageFilter {
		return func(rp *RepositoryPackage) bool { return rp.Version != version }
	}
	composed := r.Filtered(not("3-r0")).Filtered(not("2-r0"))
	got, _, err = resolveForTest(t, composed, []string{"foo"})
	require.NoError(t, err)
	require.Contains(t, got[0], "foo-1-r0 ")

	// Clone keeps the filter.
	got, _, err = resolveForTest(t, composed.Clone(), []string{"foo"})
	require.NoError(t, err)
	require.Contains(t, got[0], "foo-1-r0 ")

	// The unfiltered resolver is unaffected by its filtered copies.
	got, _, err = resolveForTest(t, r.Clone(), []string{"foo"})
	require.NoError(t, err)
	require.Contains(t, got[0], "foo-3-r0 ")
}

func TestExtendMatchesBuild(t *testing.T) {
	ctx := t.Context()
	a := loadTestIndex(t, "testdata/alpine-316/APKINDEX.tar.gz")
	b := loadTestIndex(t, "testdata/alpine-317/APKINDEX.tar.gz")
	idxA, idxB := filterTestIndex(a), filterTestIndex(b)

	base := BuildPkgResolver(ctx, []NamedIndex{idxA})
	baseNames := len(base.nameMap)
	extended := base.Extend(ctx, idxB)
	built := BuildPkgResolver(ctx, []NamedIndex{idxA, idxB})

	require.Len(t, base.nameMap, baseNames, "Extend modified the original resolver")
	require.Len(t, extended.nameMap, len(built.nameMap))
	require.Len(t, extended.installIfMap, len(built.installIfMap))
	for name, pkgs := range built.nameMap {
		require.ElementsMatch(t, pkgs, extended.nameMap[name], name)
	}
	require.Equal(t, built.installIfMap, extended.installIfMap)
	require.Equal(t, []NamedIndex{idxA, idxB}, extended.indexes)

	rng := rand.New(rand.NewPCG(3, 4)) //nolint:gosec // deterministic test data
	union := slices.Concat(a, b)
	for range 100 {
		world := []string{union[rng.IntN(len(union))].Name, union[rng.IntN(len(union))].Name}
		slices.Sort(world)
		world = slices.Compact(world)

		gotExt, _, errExt := resolveForTest(t, extended.Clone(), world)
		gotBuilt, _, errBuilt := resolveForTest(t, built.Clone(), world)
		require.Equal(t, errBuilt != nil, errExt != nil, "world %v: built err %v, extended err %v", world, errBuilt, errExt)
		require.ElementsMatch(t, gotBuilt, gotExt, "world %v", world)
	}
}

func TestExtendDoesNotShareAppendedSlices(t *testing.T) {
	ctx := t.Context()
	base := BuildPkgResolver(ctx, []NamedIndex{filterTestIndex([]*Package{
		{Name: "foo", Version: "1-r0"},
		{Name: "foo", Version: "2-r0"},
		{Name: "foo", Version: "3-r0"},
	})})
	// Three appends leave spare capacity that an in-place append would share.
	require.Greater(t, cap(base.nameMap["foo"]), len(base.nameMap["foo"]))

	four := base.Extend(ctx, filterTestIndex([]*Package{{Name: "foo", Version: "4-r0"}}))
	five := base.Extend(ctx, filterTestIndex([]*Package{{Name: "foo", Version: "5-r0"}}))

	for _, tc := range []struct {
		r    *PkgResolver
		want string
	}{{base, "foo-3-r0 "}, {four, "foo-4-r0 "}, {five, "foo-5-r0 "}} {
		got, _, err := resolveForTest(t, tc.r.Clone(), []string{"foo"})
		require.NoError(t, err)
		require.Contains(t, got[0], tc.want)
	}
	require.Len(t, four.nameMap["foo"], 4)
	require.Len(t, five.nameMap["foo"], 4)
}

func TestExtendKeepsFilter(t *testing.T) {
	ctx := t.Context()
	r := BuildPkgResolver(ctx, []NamedIndex{filterTestIndex([]*Package{{Name: "foo", Version: "1-r0"}})}).
		Filtered(func(rp *RepositoryPackage) bool { return rp.Version != "2-r0" }).
		Extend(ctx, filterTestIndex([]*Package{{Name: "foo", Version: "2-r0"}}))

	got, _, err := resolveForTest(t, r, []string{"foo"})
	require.NoError(t, err)
	require.Contains(t, got[0], "foo-1-r0 ")
}

func TestBuildPkgResolverBypassesCache(t *testing.T) {
	ctx := t.Context()
	idx1 := filterTestIndex([]*Package{{Name: "uncached-probe", Version: "1-r0"}})
	idx2 := filterTestIndex([]*Package{{Name: "uncached-probe", Version: "2-r0"}})
	_ = BuildPkgResolver(ctx, []NamedIndex{idx1}).Extend(ctx, idx2).Filtered(func(*RepositoryPackage) bool { return true })

	globalResolverCache.Lock()
	defer globalResolverCache.Unlock()
	for _, e := range globalResolverCache.entries {
		require.NotContains(t, e.indexes, idx1)
		require.NotContains(t, e.indexes, idx2)
	}
}

// TestRankedRestoresIndexOrder checks that a filtered resolver over packages
// one index contributed before another resolves as a resolver built from the
// other index does, once ranked by that index's order, where resolution
// breaks ties by position.
func TestRankedRestoresIndexOrder(t *testing.T) {
	app := &Package{Name: "app", Version: "1-r0", Dependencies: []string{"foo", "bash"}}
	foo := &Package{Name: "foo", Version: "1-r0"}
	bash := &Package{Name: "bash", Version: "5-r0"}
	completion11 := &Package{Name: "foo-bash-completion", Version: "1.1-r0", InstallIf: []string{"foo", "bash"}}
	completion10 := &Package{Name: "foo-bash-completion", Version: "1.0-r0", InstallIf: []string{"foo", "bash"}}
	checksumX := &Package{Name: "dup", Version: "1-r0", Checksum: []byte("x")}
	checksumY := &Package{Name: "dup", Version: "1-r0", Checksum: []byte("y")}

	for _, tc := range []struct {
		name string
		// first is what another index contributed earlier; index is the
		// tenant's, in its order, sharing packages with first.
		first, index []*Package
		world        []string
		want         string // name-version and checksum of the package that must win
	}{{
		name:  "first install-if package of a name",
		first: []*Package{completion11},
		index: []*Package{app, foo, bash, completion10, completion11},
		world: []string{"app"},
		want:  "foo-bash-completion-1.0-r0 ",
	}, {
		name:  "same name and version",
		first: []*Package{checksumX},
		index: []*Package{checksumY, checksumX},
		world: []string{"dup"},
		want:  fmt.Sprintf("dup-1-r0 %x ", "y"),
	}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			position := make(map[*Package]uint64, len(tc.index))
			var added []*Package
			for i, pkg := range tc.index {
				position[pkg] = uint64(i)
				if !slices.Contains(tc.first, pkg) {
					added = append(added, pkg)
				}
			}
			shared := BuildPkgResolver(ctx, []NamedIndex{filterTestIndex(tc.first)}).Extend(ctx, filterTestIndex(added))
			member := func(rp *RepositoryPackage) bool {
				_, ok := position[rp.Package]
				return ok
			}

			built, _, err := resolveForTest(t, BuildPkgResolver(ctx, []NamedIndex{filterTestIndex(tc.index)}), tc.world)
			require.NoError(t, err)
			requireWins(t, built, tc.want)

			ranked, _, err := resolveForTest(t, shared.Filtered(member).Ranked(func(rp *RepositoryPackage) uint64 { return position[rp.Package] }), tc.world)
			require.NoError(t, err)
			require.ElementsMatch(t, built, ranked)

			// Unranked, the package the other index contributed comes first.
			unranked, _, err := resolveForTest(t, shared.Filtered(member), tc.world)
			require.NoError(t, err)
			require.NotSubset(t, unranked, built)
		})
	}
}

func requireWins(t *testing.T, resolved []string, want string) {
	t.Helper()
	for _, r := range resolved {
		if strings.HasPrefix(r, want) {
			return
		}
	}
	require.Failf(t, "package not resolved", "want %q in %v", want, resolved)
}

func TestRankedKeepsSharedSlices(t *testing.T) {
	ctx := t.Context()
	r := BuildPkgResolver(ctx, []NamedIndex{filterTestIndex([]*Package{
		{Name: "foo", Version: "1-r0"},
		{Name: "foo", Version: "2-r0"},
	})})
	before := slices.Clone(r.nameMap["foo"])

	reversed := r.Ranked(func(rp *RepositoryPackage) uint64 {
		if rp.Version == "1-r0" {
			return 1
		}
		return 0
	})
	got, ok := reversed.candidates("foo")
	require.True(t, ok)
	require.Equal(t, "2-r0", got[0].Version)
	require.Equal(t, before, r.nameMap["foo"], "Ranked reordered the shared map slice")

	// A nil rank keeps the earlier one.
	got, _ = reversed.Ranked(nil).candidates("foo")
	require.Equal(t, "2-r0", got[0].Version)
}

// TestFilteredByArchMatchesPerTenant checks that resolving filtered catalog
// resolvers with GetPackagesWithDependenciesByArch disqualifies across arches
// exactly as resolving each tenant's own indexes does, and caches nothing.
func TestFilteredByArchMatchesPerTenant(t *testing.T) {
	ctx := t.Context()
	newCatalog := func() []*Package {
		return []*Package{
			{Name: "app", Version: "1-r0", Dependencies: []string{"lib"}},
			{Name: "foo", Version: "1-r0"},
			{Name: "foo", Version: "2-r0"},
			{Name: "lib", Version: "1-r0"},
			{Name: "lib", Version: "2-r0"},
		}
	}
	arches := []string{"x86_64", "aarch64"}

	for _, tc := range []struct {
		name  string
		world []string
		// tenant lists, per arch, the name-versions the tenant's repo has.
		tenant map[string][]string
		want   []string
	}{{
		name:  "newest version missing on one arch",
		world: []string{"foo"},
		tenant: map[string][]string{
			"x86_64":  {"foo-1-r0", "foo-2-r0"},
			"aarch64": {"foo-1-r0"},
		},
		want: []string{"foo-1-r0"},
	}, {
		name:  "newest version on every arch",
		world: []string{"foo"},
		tenant: map[string][]string{
			"x86_64":  {"foo-1-r0", "foo-2-r0"},
			"aarch64": {"foo-1-r0", "foo-2-r0"},
		},
		want: []string{"foo-2-r0"},
	}, {
		name:  "dependency version missing on one arch",
		world: []string{"app"},
		tenant: map[string][]string{
			"x86_64":  {"app-1-r0", "lib-1-r0", "lib-2-r0"},
			"aarch64": {"app-1-r0", "lib-1-r0"},
		},
		want: []string{"lib-1-r0", "app-1-r0"},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			catalogs := map[string]NamedIndex{}
			tenants := map[string][]NamedIndex{}
			filtered := map[string]*PkgResolver{}
			for _, arch := range arches {
				catalog := newCatalog()
				catalogs[arch] = filterTestIndex(catalog)
				var own []*Package
				for _, pkg := range catalog {
					if slices.Contains(tc.tenant[arch], pkgKey(pkg)) {
						own = append(own, pkg)
					}
				}
				tenants[arch] = []NamedIndex{filterTestIndex(own)}
				filtered[arch] = BuildPkgResolver(ctx, []NamedIndex{catalogs[arch]}).Filtered(func(rp *RepositoryPackage) bool {
					return slices.Contains(tc.tenant[arch], pkgKey(rp.Package))
				})
			}

			for _, arch := range arches {
				stock, _, err := NewPkgResolver(ctx, tenants[arch]).GetPackagesWithDependencies(ctx, tc.world, tenants)
				require.NoError(t, err)
				got, _, err := filtered[arch].GetPackagesWithDependenciesByArch(ctx, tc.world, filtered)
				require.NoError(t, err)

				render := func(pkgs []*RepositoryPackage) []string {
					keys := make([]string, 0, len(pkgs))
					for _, pkg := range pkgs {
						keys = append(keys, pkgKey(pkg.Package))
					}
					return keys
				}
				require.Equal(t, tc.want, render(stock), arch)
				require.Equal(t, tc.want, render(got), arch)
			}

			requireNotCached(t, globalResolverCache.lruCache, catalogs)
			requireNotCached(t, globalDisqualifyCache.lruCache, catalogs)
		})
	}
}

// requireNotCached checks that no entry of c is keyed by any of indexes.
func requireNotCached[V any](t *testing.T, c *lruCache[V], indexes map[string]NamedIndex) {
	t.Helper()
	c.Lock()
	defer c.Unlock()
	for _, e := range c.entries {
		for _, idx := range indexes {
			require.NotContains(t, e.indexes, idx)
		}
	}
}
