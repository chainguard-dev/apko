// Copyright 2023 Chainguard, Inc.
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
	"bufio"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"go.opentelemetry.io/otel"

	"github.com/chainguard-dev/clog"
)

var (
	parsedVersions    sync.Map // map[string]Version
	parsedConstraints sync.Map // map[string]parsedConstraint
)

// NamedIndex an index that contains all of its packages,
// as well as having an optional name and source. The name and source
// need not be unique.
type NamedIndex interface {
	Name() string
	Packages() []*RepositoryPackage
	Source() string
	Count() int
}

func indexNames(indexes []NamedIndex) []string {
	names := make([]string, len(indexes))
	for i, idx := range indexes {
		names[i] = idx.Source()
	}
	return names
}

type namedRepositoryWithIndex struct {
	name string
	repo *RepositoryWithIndex
}

func NewNamedRepositoryWithIndex(name string, repo *RepositoryWithIndex) NamedIndex {
	return &namedRepositoryWithIndex{
		name: name,
		repo: repo,
	}
}

func (n *namedRepositoryWithIndex) Name() string {
	return n.name
}

func (n *namedRepositoryWithIndex) Count() int {
	if n.repo == nil {
		return 0
	}
	return n.repo.Count()
}

func (n *namedRepositoryWithIndex) Packages() []*RepositoryPackage {
	if n.repo == nil {
		return nil
	}
	return n.repo.Packages()
}
func (n *namedRepositoryWithIndex) Source() string {
	if n.repo == nil || n.repo.IndexURI() == "" {
		return ""
	}

	return n.repo.IndexURI()
}

// repositoryPackage is a package that is part of a repository.
// it is nearly identical to RepositoryPackage, but it includes the pinned name of the repository.
type repositoryPackage struct {
	*RepositoryPackage
	pinnedName string
}

// SetRepositories sets the contents of /etc/apk/repositories file.
// The base directory of /etc/apk must already exist, i.e. this only works on an initialized APK database.
func (a *APK) SetRepositories(ctx context.Context, repos []string) error {
	ctx, span := otel.Tracer("go-apk").Start(ctx, "SetRepositories")
	defer span.End()

	clog.InfoContextf(ctx, "setting apk repositories: %v", repos)

	if len(repos) == 0 {
		return fmt.Errorf("must provide at least one repository")
	}

	data := strings.Join(repos, "\n") + "\n"

	// #nosec G306 -- apk repositories must be publicly readable
	if err := a.fs.WriteFile(filepath.Join("etc", "apk", "repositories"),
		[]byte(data), 0o644); err != nil {
		return fmt.Errorf("failed to write apk repositories list: %w", err)
	}

	return nil
}

func (a *APK) GetRepositories() (repos []string, err error) {
	// get the repository URLs
	reposFile, err := a.fs.Open(reposFilePath)
	if err != nil {
		return nil, fmt.Errorf("could not open repositories file in %s at %s: %w", a.fs, reposFilePath, err)
	}
	defer reposFile.Close()
	scanner := bufio.NewScanner(reposFile)
	for scanner.Scan() {
		repos = append(repos, scanner.Text())
	}
	return
}

// GetRepositoryIndexes returns the indexes for the repositories in the specified root.
// The signatures for each index are verified unless ignoreSignatures is set to true.
func (a *APK) GetRepositoryIndexes(ctx context.Context, ignoreSignatures bool) ([]NamedIndex, error) {
	ctx, span := otel.Tracer("go-apk").Start(ctx, "GetRepositoryIndexes")
	defer span.End()

	// get the repository URLs
	repos, err := a.GetRepositories()
	if err != nil {
		return nil, err
	}

	archFile, err := a.fs.Open(archFilePath)
	if err != nil {
		return nil, fmt.Errorf("could not open arch file in %s at %s: %w", a.fs, archFile, err)
	}
	defer archFile.Close()

	archB, err := io.ReadAll(archFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read arch file: %w", err)
	}
	// trim the newline
	arch := strings.TrimSuffix(string(archB), "\n")

	// create the list of keys
	keys := make(map[string][]byte)
	dir, err := a.fs.ReadDir(keysDirPath)
	if err != nil {
		return nil, fmt.Errorf("could not read keys directory in %s at %s: %w", a.fs, keysDirPath, err)
	}
	for _, d := range dir {
		if d.IsDir() {
			continue
		}
		fullPath := filepath.Join(keysDirPath, d.Name())
		b, err := a.fs.ReadFile(fullPath)
		if err != nil {
			return nil, fmt.Errorf("could not read key file at %s: %w", fullPath, err)
		}
		keys[d.Name()] = b
	}
	httpClient := a.client
	if a.cache != nil {
		httpClient = a.cache.client(httpClient, true)
	}
	opts := []IndexOption{WithIgnoreSignatures(ignoreSignatures),
		WithIgnoreSignatureForIndexes(a.noSignatureIndexes...),
		WithHTTPClient(httpClient),
		WithIndexAuthenticator(a.auth),
	}
	return GetRepositoryIndexes(ctx, repos, keys, arch, opts...)
}

// PkgResolver resolves packages from a list of indexes.
// It is created with NewPkgResolver and passed a list of indexes.
// It then can be used to resolve the correct version of a package given
// version constraints, if any, as well as all the package and all of
// the required upstream dependencies.
// If provided multiple indexes, it will look for dependencies in all of the
// indexes. If you need to look only in a certain set, you should create a new
// PkgResolver with only those indexes.
// If the indexes change, you should generate a new pkgResolver.
type PkgResolver struct {
	indexes      []NamedIndex
	nameMap      map[string][]*repositoryPackage
	installIfMap map[string][]*repositoryPackage // contains any package that should be installed if the named package is installed

	// Short-circuit providers we have already selected.
	selected map[string]*RepositoryPackage
}

// Clone returns a copy of PkgResolver.
func (p *PkgResolver) Clone() *PkgResolver {
	return &PkgResolver{
		indexes:      p.indexes,
		nameMap:      maps.Clone(p.nameMap),
		installIfMap: maps.Clone(p.installIfMap),
		selected:     map[string]*RepositoryPackage{},
	}
}

// NewPkgResolver creates a new pkgResolver from a list of indexes.
// The indexes are anything that implements NamedIndex.
func NewPkgResolver(ctx context.Context, indexes []NamedIndex) *PkgResolver {
	return globalResolverCache.Get(ctx, indexes)
}

func newPkgResolver(ctx context.Context, indexes []NamedIndex) *PkgResolver {
	_, span := otel.Tracer("go-apk").Start(ctx, "NewPkgResolver")
	defer span.End()

	numPackages := 0
	for _, index := range indexes {
		numPackages += index.Count()
	}

	var (
		pkgNameMap   = make(map[string][]*repositoryPackage, numPackages)
		installIfMap = map[string][]*repositoryPackage{}
	)
	p := &PkgResolver{
		indexes:  indexes,
		selected: map[string]*RepositoryPackage{},
	}

	// create a map of every package by name and version to its RepositoryPackage
	for _, index := range indexes {
		for _, pkg := range index.Packages() {
			pkgNameMap[pkg.Name] = append(pkgNameMap[pkg.Name], &repositoryPackage{
				RepositoryPackage: pkg,
				pinnedName:        index.Name(),
			})
			for _, dep := range pkg.InstallIf {
				if _, ok := installIfMap[dep]; !ok {
					installIfMap[dep] = []*repositoryPackage{}
				}
				installIfMap[dep] = append(installIfMap[dep], &repositoryPackage{
					RepositoryPackage: pkg,
					pinnedName:        index.Name(),
				})
			}
		}
	}
	// create a map of every provided file to its package
	allPkgs := make([][]*repositoryPackage, 0, len(pkgNameMap))
	for _, pkgVersions := range pkgNameMap {
		allPkgs = append(allPkgs, pkgVersions)
	}
	for _, pkgVersions := range allPkgs {
		for _, pkg := range pkgVersions {
			for _, provide := range pkg.Provides {
				name := cachedResolvePackageNameVersionPin(provide).name
				pkgNameMap[name] = append(pkgNameMap[name], pkg)
			}
		}
	}
	p.nameMap = pkgNameMap
	p.installIfMap = installIfMap
	return p
}

// We select the next package based on the smallest number of candidate packages.
func (p *PkgResolver) nextPackage(packages []string, dq map[*RepositoryPackage]string) (string, error) {
	next := ""
	leastDeps := 0

	// first get the explicitly named packages
	for _, pkgName := range packages {
		pkgs, err := p.ResolvePackage(pkgName, dq)
		if err != nil {
			return "", &ConstraintError{pkgName, err}
		}
		if len(pkgs) == 0 {
			return "", fmt.Errorf("could not find package %s", pkgName)
		}

		if next == "" {
			next = pkgName
			leastDeps = len(pkgs)
			continue
		}

		if deps := len(pkgs); deps < leastDeps {
			next = pkgName
			leastDeps = deps
		}
	}

	return next, nil
}

// Disqualify anything that provides "constraint". This is used for !foo style constraints.
func (p *PkgResolver) disqualifyProviders(constraint string, dq map[*RepositoryPackage]string) {
	parsed := cachedResolvePackageNameVersionPin(constraint)
	providers, ok := p.nameMap[parsed.name]
	if !ok {
		return
	}

	conflicting := filterPackages(providers, dq, withVersion(parsed.version, parsed.dep), withPreferPin(parsed.pin))

	for _, conflict := range conflicting {
		if _, dqed := dq[conflict.RepositoryPackage]; dqed {
			// Already disqualified, don't bother generating reason.
			continue
		}

		p.disqualify(dq, conflict.RepositoryPackage, "excluded by !"+constraint)
	}
}

func (p *PkgResolver) conflictingVersion(constraint parsedConstraint, conflict *repositoryPackage) bool {
	// If the constraint is not a virtual, everything will conflict with it.
	// TODO: Figure out if this logic is actually equivalent to how apk disqualifies virtual.
	if constraint.version != "" {
		return true
	}

	// From here on, "the same version" really means it's a virtual, but let's keep the diff small until we revisit.

	if conflict.Name == constraint.name {
		return conflict.Version != constraint.version
	}

	for _, confProv := range conflict.Provides {
		confConstraint := cachedResolvePackageNameVersionPin(confProv)
		if confConstraint.name != constraint.name {
			// Not the constraint we're looking for.
			continue
		}

		if confConstraint.version == constraint.version {
			// If the versions are the same, they shouldn't conflict.
			return false
		}

		return true
	}

	panic("conflictingVersion called with a package that does not provide the constraint")
}

// Disqualify anything that conflicts with the given pkg.
func (p *PkgResolver) disqualifyConflicts(pkg *RepositoryPackage, dq map[*RepositoryPackage]string) {
	for _, prov := range pkg.Provides {
		constraint := cachedResolvePackageNameVersionPin(prov)
		providers, ok := p.nameMap[constraint.name]
		if !ok {
			continue
		}

		for _, conflict := range providers {
			if conflict.RepositoryPackage == pkg {
				continue
			}

			if _, dqed := dq[conflict.RepositoryPackage]; dqed {
				// Already disqualified, don't bother generating reason.
				continue
			}

			if !p.conflictingVersion(constraint, conflict) {
				// The conflicting package provides the given name but the version is the same, so no conflict.
				continue
			}

			p.disqualify(dq, conflict.RepositoryPackage, pkg.Filename()+" already provides "+constraint.name)
		}
	}
}

func (p *PkgResolver) pick(pkg *RepositoryPackage) error {
	if conflict, ok := p.selected[pkg.Name]; ok {
		// Trying to re-select the same thing is fine actually.
		if conflict == pkg {
			return nil
		}

		return fmt.Errorf("selecting package %s conflicts with %s on %q", pkg.Filename(), conflict.Filename(), pkg.Name)
	}

	p.selected[pkg.Name] = pkg

	for _, prov := range pkg.Provides {
		constraint := cachedResolvePackageNameVersionPin(prov)
		if conflict, ok := p.selected[constraint.name]; ok {
			return fmt.Errorf("selecting package %s conflicts with %s on %q", pkg.Filename(), conflict.Filename(), constraint.name)
		}
		p.selected[constraint.name] = pkg
	}

	return nil
}

func (p *PkgResolver) disqualify(dq map[*RepositoryPackage]string, pkg *RepositoryPackage, reason string) {
	dq[pkg] = reason

	// TODO: Ripple up and disqualify anything that is no longer solveable.
}

// constrain looks through a list of constraints and disqualifies anything that would
// conflict with any constraints that have a version selector (i.e. not versionAny).
func (p *PkgResolver) constrain(constraints []string, dq map[*RepositoryPackage]string) error {
	for _, constraint := range constraints {
		if strings.HasPrefix(constraint, "!") {
			p.disqualifyProviders(constraint[1:], dq)
			continue
		}

		parsed := cachedResolvePackageNameVersionPin(constraint)
		if parsed.dep == versionAny {
			continue
		}

		providers, ok := p.nameMap[parsed.name]
		if !ok {
			continue
		}

		requiredVersion, err := cachedParseVersion(parsed.version)
		if err != nil {
			// This shouldn't happen but return an error to be safe.
			return fmt.Errorf("parsing constraint %q: %w", constraint, err)
		}

		for _, provider := range providers {
			if provider.Name == parsed.name {
				actualVersion, err := cachedParseVersion(provider.Version)
				// skip invalid ones
				if err != nil {
					p.disqualify(dq, provider.RepositoryPackage, fmt.Sprintf("parsing version %q failed: %v", provider.Version, err))
					continue
				}

				if !parsed.dep.satisfies(actualVersion, requiredVersion) {
					p.disqualify(dq, provider.RepositoryPackage, fmt.Sprintf("%q does not satisfy %q", provider.Version, constraint))
				}
			} else {
				for _, provides := range provider.Provides {
					pp := cachedResolvePackageNameVersionPin(provides)
					if pp.name != parsed.name {
						continue
					}
					actualVersion, err := cachedParseVersion(pp.version)
					// skip invalid ones
					if err != nil {
						dq[provider.RepositoryPackage] = fmt.Sprintf("parsing %q: %v", pp.version, err)
						continue
					}
					if !parsed.dep.satisfies(actualVersion, requiredVersion) {
						dq[provider.RepositoryPackage] = fmt.Sprintf("%q provides %q which does not satisfy %q", provider.Filename(), provides, constraint)
					}
				}
			}
		}
	}

	return nil
}

// GetPackagesWithDependencies get all of the dependencies for the given packages based on the
// indexes. Does not filter for installed already or not.
func (p *PkgResolver) GetPackagesWithDependencies(ctx context.Context, packages []string, allArchs map[string][]NamedIndex) (toInstall []*RepositoryPackage, conflicts []string, err error) {
	_, span := otel.Tracer("go-apk").Start(ctx, "GetPackagesWithDependencies")
	defer span.End()

	// Tracks all the packages we have disqualified and the reason we disqualified them.
	dq := globalDisqualifyCache.Get(ctx, allArchs)

	// We're going to mutate this as our set of input packages to install, so make a copy.
	constraints := slices.Clone(packages)

	var (
		dependenciesMap = make(map[string]*RepositoryPackage, len(packages))
		installTracked  = map[string]*RepositoryPackage{}
	)

	if err := p.constrain(constraints, dq); err != nil {
		return nil, nil, fmt.Errorf("constraining initial packages: %w", err)
	}

	for len(constraints) != 0 {
		next, err := p.nextPackage(constraints, dq)
		if err != nil {
			return nil, nil, err
		}

		pkg, err := p.resolvePackage(next, dq)
		if err != nil {
			return nil, nil, &ConstraintError{next, err}
		}

		// do not add it to toInstall, as we want to have it in the correct order with dependencies
		dependenciesMap[pkg.Name] = pkg

		// Remove it from contraints.
		constraints = slices.DeleteFunc(constraints, func(s string) bool {
			return s == next
		})

		p.disqualifyConflicts(pkg, dq)
	}

	// now get the dependencies for each package
	for _, pkgName := range packages {
		pkg, deps, confs, err := p.GetPackageWithDependencies(ctx, pkgName, dependenciesMap, dq)
		if err != nil {
			return toInstall, nil, &ConstraintError{pkgName, err}
		}

		for _, dep := range deps {
			if _, ok := installTracked[dep.Name]; !ok {
				toInstall = append(toInstall, dep)
				installTracked[dep.Name] = dep
			}
			if _, ok := dependenciesMap[dep.Name]; !ok {
				dependenciesMap[dep.Name] = dep
			}
		}
		if _, ok := installTracked[pkg.Name]; !ok {
			toInstall = append(toInstall, pkg)
			installTracked[pkg.Name] = pkg
		}
		if _, ok := dependenciesMap[pkg.Name]; !ok {
			dependenciesMap[pkg.Name] = pkg
		}
		conflicts = append(conflicts, confs...)
	}

	conflicts = uniqify(conflicts)

	return toInstall, conflicts, nil
}

// GetPackageWithDependencies get all of the dependencies for a single package as well as looking
// up the package itself and resolving its version, based on the indexes.
// Requires the existing set because the logic for resolving dependencies between competing
// options may depend on whether or not one already is installed.
// Must not modify the existing map directly.
func (p *PkgResolver) GetPackageWithDependencies(ctx context.Context, pkgName string, existing map[string]*RepositoryPackage, dq map[*RepositoryPackage]string) (*RepositoryPackage, []*RepositoryPackage, []string, error) {
	parents := make(map[string]bool)
	localExisting := make(map[string]*RepositoryPackage, len(existing))
	existingOrigins := map[string]bool{}
	for k, v := range existing {
		localExisting[k] = v
		if v != nil && v.Origin != "" {
			existingOrigins[v.Origin] = true
		}
	}

	pkg, err := p.resolvePackage(pkgName, dq)
	if err != nil {
		return nil, nil, nil, err
	}

	pin := cachedResolvePackageNameVersionPin(pkgName).pin
	deps, conflicts, err := p.getPackageDependencies(ctx, pkg, pin, parents, localExisting, existingOrigins, dq)
	if err != nil {
		return nil, nil, nil, err
	}

	// eliminate duplication in dependencies
	added := make(map[string]*RepositoryPackage, len(deps))
	dependencies := make([]*RepositoryPackage, 0, len(deps))
	for _, dep := range deps {
		if _, ok := added[dep.Name]; !ok {
			dependencies = append(dependencies, dep)
			added[dep.Name] = dep
		}
	}
	// are there any installIf dependencies?
	for dep, depPkg := range added {
		depPkgList, ok := p.installIfMap[dep]
		if !ok {
			depPkgList, ok = p.installIfMap[fmt.Sprintf("%s=%s", dep, depPkg.Version)]
		}
		if !ok {
			continue
		}
		// this package "dep" can trigger an installIf. It might not be enough, so check it
		for _, installIfPkg := range depPkgList {
			var matchCount int
			for _, subDep := range installIfPkg.InstallIf {
				// two possibilities: package name, or name=version
				constraint := cachedResolvePackageNameVersionPin(subDep)
				name, version := constraint.name, constraint.version
				// precise match of whatever it is, take it and continue
				if _, ok := added[subDep]; ok {
					matchCount++
					continue
				}
				// didn't get a precise match, so check if the name and version match
				if addedPkg, ok := added[name]; ok && addedPkg.Version == version {
					matchCount++
					continue
				}
			}
			if matchCount == len(installIfPkg.InstallIf) {
				// all dependencies are met, so add it
				if _, ok := added[installIfPkg.Name]; !ok {
					dependencies = append(dependencies, installIfPkg.RepositoryPackage)
					added[installIfPkg.Name] = installIfPkg.RepositoryPackage
				}
			}
		}
	}
	return pkg, dependencies, conflicts, nil
}

// ResolvePackage given a single package name and optional version constraints, resolve to a list of packages
// that satisfy the constraint. The list will be sorted by version number, with the highest version first
// and decreasing from there. In general, the first one in the list is the best match. This function
// returns multiple in case you need to see all potential matches.
func (p *PkgResolver) ResolvePackage(pkgName string, dq map[*RepositoryPackage]string) ([]*RepositoryPackage, error) {
	constraint := cachedResolvePackageNameVersionPin(pkgName)
	name, version, compare, pin := constraint.name, constraint.version, constraint.dep, constraint.pin
	pkgsWithVersions, ok := p.nameMap[name]
	if !ok {
		return nil, fmt.Errorf("could not find package that provides %s in indexes", pkgName)
	}

	// pkgsWithVersions contains a map of all versions of the package
	// get the one that most matches what was requested
	packages := filterPackages(pkgsWithVersions, dq, withVersion(version, compare), withPreferPin(pin))
	if len(packages) == 0 {
		return nil, maybedqerror(pkgName, pkgsWithVersions, dq)
	}
	p.sortPackages(packages, nil, name, nil, nil, pin)
	pkgs := make([]*RepositoryPackage, 0, len(packages))
	for _, pkg := range packages {
		if _, dqed := dq[pkg.RepositoryPackage]; dqed {
			continue
		}
		pkgs = append(pkgs, pkg.RepositoryPackage)
	}
	return pkgs, nil
}

// This is like ResolvePackage but we only care about the best match and not all matches.
func (p *PkgResolver) resolvePackage(pkgName string, dq map[*RepositoryPackage]string) (*RepositoryPackage, error) {
	constraint := cachedResolvePackageNameVersionPin(pkgName)
	name, version, compare, pin := constraint.name, constraint.version, constraint.dep, constraint.pin

	pkgsWithVersions, ok := p.nameMap[name]
	if !ok {
		return nil, fmt.Errorf("could not find package, alias or a package that provides %s in indexes", pkgName)
	}

	// pkgsWithVersions contains a map of all versions of the package
	// get the one that most matches what was requested
	packages := filterPackages(pkgsWithVersions, dq, withVersion(version, compare), withPreferPin(pin))
	if len(packages) == 0 {
		return nil, maybedqerror(pkgName, pkgsWithVersions, dq)
	}
	return p.bestPackage(packages, nil, name, nil, nil, pin).RepositoryPackage, nil
}

// getPackageDependencies get all of the dependencies for a single package based on the
// indexes. Internal version includes passed arg for preventing infinite loops.
// checked map is passed as an arg, rather than a member of the struct, because
// it is unique to each lookup.
//
// The logic for dependencies in order is:
// 1. deeper before shallower
// 2. order of presentation
//
// for 2 dependencies at the same level, it is the first before the second
// for 2 dependencies one parent to the other, is is the child before the parent
//
// this means the logic for walking the tree is depth-first, down before across
// to do this correctly, we also need to handle duplicates and loops.
// For example
//
//	A -> B -> C -> D
//	  -> C -> D
//
// We do not want to get C or D twice, or even have it appear on the list twice.
// The final result should include each of A,B,C,D exactly once, and in the correct order.
// That order should be: D, C, B, A
// The initial run will be D,C,B,D,C,A, which then should get simplified to D,C,B,A
// In addition, we need to ensure that we don't loop, for example, if D should point somehow to B
// or itself. We need a "checked" list that says, "already got the one this is pointing at".
// It might change the order of install.
// In other words, this _should_ be a DAG (acyclical), but because the packages
// are just listing dependencies in text, it might be cyclical. We need to be careful of that.
func (p *PkgResolver) getPackageDependencies(ctx context.Context, pkg *RepositoryPackage, allowPin string, parents map[string]bool, existing map[string]*RepositoryPackage, existingOrigins map[string]bool, dq map[*RepositoryPackage]string) (dependencies []*RepositoryPackage, conflicts []string, err error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, context.Cause(ctx)
	}
	// check if the package we are checking is one of our parents, avoid cyclical graphs
	if _, ok := parents[pkg.Name]; ok {
		return nil, nil, nil
	}
	myProvides := make(map[string]bool, 2*len(pkg.Provides))
	// see if we provide this
	for _, provide := range pkg.Provides {
		name := cachedResolvePackageNameVersionPin(provide).name
		myProvides[provide] = true
		myProvides[name] = true
	}

	constraints := slices.Clone(pkg.Dependencies)

	if err := p.constrain(constraints, dq); err != nil {
		return nil, nil, fmt.Errorf("constraining deps for %q: %w", pkg.Filename(), err)
	}

	for len(constraints) != 0 {
		options := map[string][]*repositoryPackage{}

		// each dependency has only one of two possibilities:
		// - !name     - "I cannot be installed along with the package <name>"
		// - name      - "I need package 'name'" -OR- "I need the package that provides <name>"
		for _, dep := range constraints {
			if strings.HasPrefix(dep, "!") {
				// TODO: This is a little strange, we should revisit why we do this.
				conflicts = append(conflicts, dep[1:])

				// If it was a conflict, we don't need to find a provider.
				continue
			}

			// this package might be pinned to a version
			constraint := cachedResolvePackageNameVersionPin(dep)
			name, version, compare := constraint.name, constraint.version, constraint.dep
			// see if we provide this
			if myProvides[name] || myProvides[dep] {
				// we provide this, so skip it
				continue
			}

			if pkg.Name == name {
				var (
					actualVersion, requiredVersion Version
					err1, err2                     error
				)
				actualVersion, err1 = cachedParseVersion(pkg.Version)
				if compare != versionAny {
					requiredVersion, err2 = cachedParseVersion(version)
				}
				// we accept invalid versions for ourself, but do not try to use it to fulfill
				if err1 == nil && err2 == nil {
					if compare.satisfies(actualVersion, requiredVersion) {
						// we provide it, so skip looking elsewhere
						continue
					}
				}
			}

			if picked, ok := p.selected[name]; ok {
				if version == "" {
					// If we don't care which version, and we've already selected something, fantastic.
					continue
				}

				actualVersion, err := cachedParseVersion(picked.Version)
				if err != nil {
					return nil, nil, err
				}
				requiredVersion, err := cachedParseVersion(version)
				if err != nil {
					return nil, nil, err
				}

				// We do care which version and they match.
				if compare.satisfies(actualVersion, requiredVersion) {
					continue
				}

				// We already selected something to satisfy "name" and it does not match the "version" we need now.
				return nil, nil, fmt.Errorf("we already selected %q=%q which conflicts with %q=%q", picked.Name, picked.Version, name, version)
			}

			// first see if it is a name of a package
			depPkgWithVersions, ok := p.nameMap[name]
			if !ok {
				return nil, nil, fmt.Errorf("could not find package either named %s or that provides %s for %s", dep, dep, pkg.Name)
			}
			// pkgsWithVersions contains a map of all versions of the package
			// get the one that most matches what was requested
			pkgs := filterPackages(depPkgWithVersions,
				dq,
				withVersion(version, compare),
				withAllowPin(allowPin),
				withInstalledPackage(existing[name]),
			)
			if len(pkgs) == 0 {
				return nil, nil, &DepError{pkg, maybedqerror(dep, depPkgWithVersions, dq)}
			}
			options[dep] = pkgs
		}

		constraints = slices.Collect(maps.Keys(options))
		if len(constraints) == 0 {
			// Nothing left to solve.
			continue
		}

		// Find the constraint with the fewest solutions.
		lowest := ""
		for k, v := range options {
			if lowest == "" || len(v) < len(options[lowest]) {
				lowest = k
			} else if len(v) == len(options[lowest]) && k < lowest {
				// This is a little janky, but since map order is non-deterministic, we want to break ties.
				lowest = k
			}
		}

		pkgs := options[lowest]
		name := cachedResolvePackageNameVersionPin(lowest).name

		// Remove this from our constraints.
		constraints = slices.DeleteFunc(constraints, func(s string) bool {
			return s == lowest
		})

		best := p.bestPackage(pkgs, nil, name, existing, existingOrigins, "")
		if best == nil {
			return nil, nil, fmt.Errorf("could not find package for %q", name)
		}

		depPkg := best.RepositoryPackage
		p.disqualifyConflicts(depPkg, dq)

		// and then recurse to its children
		// each child gets the parental chain, but should not affect any others,
		// so we duplicate the map for the child
		childParents := map[string]bool{}
		for k := range parents {
			childParents[k] = true
		}
		childParents[pkg.Name] = true

		if err := p.pick(pkg); err != nil {
			return nil, nil, err
		}

		subDeps, confs, err := p.getPackageDependencies(ctx, depPkg, allowPin, childParents, existing, existingOrigins, dq)
		if err != nil {
			return nil, nil, &DepError{pkg, err}
		}
		// first add the children, then the parent (depth-first)
		dependencies = append(dependencies, subDeps...)
		dependencies = append(dependencies, depPkg)
		conflicts = append(conflicts, confs...)
		for _, dep := range subDeps {
			existing[dep.Name] = dep
			existingOrigins[dep.Origin] = true
		}
	}
	return dependencies, conflicts, nil
}

func cachedParseVersion(version string) (Version, error) {
	pkg, ok := parsedVersions.Load(version)
	if ok {
		return pkg.(Version), nil
	}

	parsed, err := ParseVersion(version)
	if err != nil {
		return parsed, err
	}

	parsedVersions.Store(version, parsed)
	return parsed, nil
}

func cachedResolvePackageNameVersionPin(pkgName string) parsedConstraint {
	cached, ok := parsedConstraints.Load(pkgName)
	if ok {
		return cached.(parsedConstraint)
	}

	pin := resolvePackageNameVersionPin(pkgName)

	parsedConstraints.Store(pkgName, pin)
	return pin
}

// sortPackages sorts a slice of packages in descending order of preference, based on
// matching origin to a provided comparison package, whether or not one of the packages
// already is installed, the versions, and whether an origin already exists.
// The pin is for preference only; prefer a package that matches the pin over one that does not.
// If a name is provided, then this is indicated as the name of the package we are looking for.
// This may affect the sort order, as not all packages may have the same name.
// For example, if the original search was for package "a", then pkgs may contain some that
// are named "a", but others that provided "a". In that case, we should look not at the
// version of the package, but the version of "a" that the package provides.
func (p *PkgResolver) sortPackages(pkgs []*repositoryPackage, compare *RepositoryPackage, name string, existing map[string]*RepositoryPackage, existingOrigins map[string]bool, pin string) {
	slices.SortFunc(pkgs, p.comparePackages(compare, name, existing, existingOrigins, pin))
}

func (p *PkgResolver) comparePackages(compare *RepositoryPackage, name string, existing map[string]*RepositoryPackage, existingOrigins map[string]bool, pin string) func(a, b *repositoryPackage) int { //nolint:gocyclo
	return func(a, b *repositoryPackage) int {
		// determine versions
		iVersionStr := p.getDepVersionForName(a, name)
		jVersionStr := p.getDepVersionForName(b, name)
		if compare != nil {
			// matching repository
			pkgRepo := compare.Repository().URI
			iRepo := a.Repository().URI
			jRepo := b.Repository().URI
			if iRepo == pkgRepo && jRepo != pkgRepo {
				return -1
			}
			if jRepo == pkgRepo && iRepo != pkgRepo {
				return 1
			}
			// matching origin with compare
			pkgOrigin := compare.Origin
			iOrigin := a.Origin
			jOrigin := b.Origin
			if iOrigin == pkgOrigin && jOrigin != pkgOrigin {
				return -1
			}
			if jOrigin == pkgOrigin && iOrigin != pkgOrigin {
				return 1
			}
		}
		// see if one already is installed
		iMatched, iOk := existing[a.Name]
		jMatched, jOk := existing[b.Name]

		// because existing takes priority, if either matches, we should take it
		// check if the first matches
		if iOk && iMatched.Version == a.Version && (!jOk || jMatched.Version != b.Version) {
			return -1
		}
		// the first did not match, check if the second matches
		if jOk && jMatched.Version == b.Version && (!iOk || iMatched.Version != a.Version) {
			return 1
		}
		// both matched, so keep looking

		// see if an origin already is installed
		iOriginMatched := existingOrigins[a.Origin]
		jOriginMatched := existingOrigins[b.Origin]
		if iOriginMatched && !jOriginMatched {
			return -1
		}
		if jOriginMatched && !iOriginMatched {
			return 1
		}

		if a.pinnedName == pin && b.pinnedName != pin {
			return -1
		}
		if a.pinnedName != pin && b.pinnedName == pin {
			return 1
		}

		// check provider priority
		if a.ProviderPriority != b.ProviderPriority {
			if a.ProviderPriority > b.ProviderPriority {
				return -1
			}

			// a < b
			return 1
		}
		// both matched or both did not, so just compare versions
		// version priority
		iVersion, err := cachedParseVersion(iVersionStr)
		if err != nil {
			return 1
		}
		jVersion, err := cachedParseVersion(jVersionStr)
		if err != nil {
			// If j fails to parse, prefer i.
			return -1
		}
		versions := CompareVersions(iVersion, jVersion)
		if versions != equal {
			return -1 * versions
		}
		// if versions are equal, they might not be the same as the package versions
		if iVersionStr != a.Version || jVersionStr != b.Version {
			iVersion, err := cachedParseVersion(a.Version)
			if err != nil {
				return 1
			}
			jVersion, err := cachedParseVersion(b.Version)
			if err != nil {
				// If j fails to parse, prefer i.
				return -1
			}
			versions := CompareVersions(iVersion, jVersion)
			if versions != equal {
				return -1 * versions
			}
		}
		// if versions are equal, compare names
		return cmp.Compare(a.Name, b.Name)
	}
}

func (p *PkgResolver) bestPackage(pkgs []*repositoryPackage, compare *RepositoryPackage, name string, existing map[string]*RepositoryPackage, existingOrigins map[string]bool, pin string) *repositoryPackage {
	if len(pkgs) == 0 {
		return nil
	}
	return slices.MinFunc(pkgs, p.comparePackages(compare, name, existing, existingOrigins, pin))
}

// getDepVersionForName get the version of the package that provides the given name.
// If the name matches the package name, then the version of the package is used;
// if it does not, then the version of the provides is used.
//
// For example, if pkg foo v2.3 provides bar=1.2, and we look for name=bar then it returns
// 1.2 (from the provides); else it return 2.3 (from the package itself).
//
// Note that the calling function might decide to ignore this and use the package
// version anyways.
func (p *PkgResolver) getDepVersionForName(pkg *repositoryPackage, name string) string {
	if name == "" || name == pkg.Name {
		return pkg.Version
	}
	for _, prov := range pkg.Provides {
		constraint := cachedResolvePackageNameVersionPin(prov)
		pName, pVersion := constraint.name, constraint.version
		if pVersion == "" {
			pVersion = pkg.Version
		}
		if pName == name {
			return pVersion
		}
	}
	return ""
}

type ConstraintError struct {
	Constraint string
	Wrapped    error
}

func (e *ConstraintError) Unwrap() error {
	return e.Wrapped
}

func (e *ConstraintError) Error() string {
	return fmt.Sprintf("solving %q constraint: %s", e.Constraint, e.Wrapped.Error())
}

type DepError struct {
	Package *RepositoryPackage
	Wrapped error
}

func (e *DepError) Unwrap() error {
	return e.Wrapped
}

func (e *DepError) Error() string {
	return fmt.Sprintf("resolving %q deps:\n%s", e.Package.Filename(), e.Wrapped.Error())
}

type DisqualifiedError struct {
	Package *RepositoryPackage
	Wrapped error
}

func (e *DisqualifiedError) Error() string {
	return fmt.Sprintf("  %s disqualified because %s", e.Package.Filename(), e.Wrapped.Error())
}

func (e *DisqualifiedError) Unwrap() error {
	return e.Wrapped
}

func maybedqerror(constraint string, pkgs []*repositoryPackage, dq map[*RepositoryPackage]string) error {
	errs := make([]error, 0, len(pkgs))
	for _, pkg := range pkgs {
		reason, ok := dq[pkg.RepositoryPackage]
		if ok {
			errs = append(errs, &DisqualifiedError{pkg.RepositoryPackage, errors.New(reason)})
		}
	}

	if len(errs) != 0 {
		return &ConstraintError{constraint, errors.Join(errs...)}
	}

	return fmt.Errorf("could not find constraint %q in indexes", constraint)
}

func disqualifyDifference(ctx context.Context, byArch map[string][]NamedIndex) map[*RepositoryPackage]string {
	dq := map[*RepositoryPackage]string{}

	if len(byArch) == 1 {
		// There is no difference between archs if we have one arch.
		return dq
	}

	// arch -> name -> set[version]
	allowablePackages := map[string]map[string]map[string]struct{}{}

	for arch, indexes := range byArch {
		// Build up a map per arch to quickly check existence of a package name+version.
		allowed := map[string]map[string]struct{}{}
		for _, index := range indexes {
			for _, pkg := range index.Packages() {
				versions, ok := allowed[pkg.Name]
				if !ok {
					versions = map[string]struct{}{}
				}
				versions[pkg.Version] = struct{}{}
				allowed[pkg.Name] = versions
			}
		}
		allowablePackages[arch] = allowed
	}

	for arch := range allowablePackages {
		p := newPkgResolver(ctx, byArch[arch])
		for otherArch, allowed := range allowablePackages {
			if otherArch == arch {
				continue
			}

			for _, pkgVersions := range p.nameMap {
				for _, pkg := range pkgVersions {
					versions, ok := allowed[pkg.Name]
					if !ok {
						dq[pkg.RepositoryPackage] = fmt.Sprintf("package %q not available for arch %q", pkg.Filename(), otherArch)
						continue
					}
					if _, ok := versions[pkg.Version]; !ok {
						dq[pkg.RepositoryPackage] = fmt.Sprintf("package %q not available for arch %q", pkg.Filename(), otherArch)
					}
				}
			}
		}
	}

	return dq
}
