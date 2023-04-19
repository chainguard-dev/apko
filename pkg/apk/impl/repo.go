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

package impl

import (
	"bufio"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"gitlab.alpinelinux.org/alpine/go/repository"
)

// NamedIndex an index that contains all of its packages,
// as well as having an optional name and source. The name and source
// need not be unique.
type NamedIndex interface {
	Name() string
	Packages() []*repository.RepositoryPackage
	Source() string
}

type namedRepositoryWithIndex struct {
	name string
	repo *repository.RepositoryWithIndex
}

func NewNamedRepositoryWithIndex(name string, repo *repository.RepositoryWithIndex) *namedRepositoryWithIndex {
	return &namedRepositoryWithIndex{
		name: name,
		repo: repo,
	}
}

func (n *namedRepositoryWithIndex) Name() string {
	return n.name
}

func (n *namedRepositoryWithIndex) Packages() []*repository.RepositoryPackage {
	if n.repo == nil {
		return nil
	}
	return n.repo.Packages()
}
func (n *namedRepositoryWithIndex) Source() string {
	if n.repo == nil || n.repo.IndexUri() == "" {
		return ""
	}

	return n.repo.IndexUri()
}

// repositoryPackage is a package that is part of a repository.
// it is nearly identical to repository.RepositoryPackage, but it includes the pinned name of the repository.
type repositoryPackage struct {
	*repository.RepositoryPackage
	pinnedName string
}

// SetRepositories sets the contents of /etc/apk/repositories file.
// The base directory of /etc/apk must already exist, i.e. this only works on an initialized APK database.
func (a *APKImplementation) SetRepositories(repos []string) error {
	a.logger.Infof("setting apk repositories")

	data := strings.Join(repos, "\n")

	// #nosec G306 -- apk repositories must be publicly readable
	if err := a.fs.WriteFile(filepath.Join("etc", "apk", "repositories"),
		[]byte(data), 0o644); err != nil {
		return fmt.Errorf("failed to write apk repositories list: %w", err)
	}

	return nil
}

func (a *APKImplementation) GetRepositories() (repos []string, err error) {
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

// getRepositoryIndexes returns the indexes for the repositories in the specified root.
// The signatures for each index are verified unless ignoreSignatures is set to true.
func (a *APKImplementation) getRepositoryIndexes(ignoreSignatures bool) ([]*namedRepositoryWithIndex, error) {
	// get the repository URLs
	repos, err := a.GetRepositories()
	if err != nil {
		return nil, err
	}

	archFile, err := a.fs.Open(archFilePath)
	if err != nil {
		return nil, fmt.Errorf("could not open arch file in %s at %s: %w", a.fs, archFile, err)
	}
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

	return GetRepositoryIndexes(repos, keys, arch, WithIgnoreSignatures(ignoreSignatures), WithHTTPClient(a.client))
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
	providesMap  map[string][]*repositoryPackage
	installIfMap map[string][]*repositoryPackage // contains any package that should be installed if the named package is installed
}

// NewPkgResolver creates a new pkgResolver from a list of indexes.
// The indexes are anything that implements NamedIndex.
func NewPkgResolver(indexes []NamedIndex) *PkgResolver {
	var (
		pkgNameMap     = map[string][]*repositoryPackage{}
		pkgProvidesMap = map[string][]*repositoryPackage{}
		installIfMap   = map[string][]*repositoryPackage{}
	)
	p := &PkgResolver{
		indexes: indexes,
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
	allPkgs := make([][]*repositoryPackage, 0, 10)
	for _, pkgVersions := range pkgNameMap {
		allPkgs = append(allPkgs, pkgVersions)
	}
	for _, pkgVersions := range allPkgs {
		for _, pkg := range pkgVersions {
			for _, provide := range pkg.Provides {
				name, _, _, _ := resolvePackageNameVersionPin(provide)
				pkgNameMap[name] = append(pkgNameMap[name], pkg)
				if _, ok := pkgProvidesMap[name]; !ok {
					pkgProvidesMap[name] = []*repositoryPackage{}
				}
				pkgProvidesMap[name] = append(pkgProvidesMap[name], pkg)
			}
		}
	}
	p.nameMap = pkgNameMap
	p.providesMap = pkgProvidesMap
	p.installIfMap = installIfMap
	return p
}

// GetPackagesWithDependencies get all of the dependencies for the given packages based on the
// indexes. Does not filter for installed already or not.
func (p *PkgResolver) GetPackagesWithDependencies(packages []string) (toInstall []*repository.RepositoryPackage, conflicts []string, err error) {
	var (
		dependenciesMap = map[string]*repository.RepositoryPackage{}
		installTracked  = map[string]*repository.RepositoryPackage{}
	)
	// first get the explicitly named packages
	for _, pkgName := range packages {
		pkgs, err := p.ResolvePackage(pkgName)
		if err != nil {
			return nil, nil, err
		}
		if len(pkgs) == 0 {
			return nil, nil, fmt.Errorf("could not find package %s", pkgName)
		}
		// do not add it to toInstall, as we want to have it in the correct order with dependencies
		dependenciesMap[pkgName] = pkgs[0]
	}
	// now get the dependencies for each package
	for _, pkgName := range packages {
		pkg, deps, confs, err := p.GetPackageWithDependencies(pkgName, dependenciesMap)
		if err != nil {
			return nil, nil, err
		}
		for _, dep := range deps {
			if _, ok := installTracked[dep.Name]; !ok {
				toInstall = append(toInstall, dep)
				installTracked[dep.Name] = dep
			}
			dependenciesMap[dep.Name] = dep
		}
		toInstall = append(toInstall, pkg)
		installTracked[pkg.Name] = pkg
		if _, ok := dependenciesMap[pkgName]; !ok {
			dependenciesMap[pkgName] = pkg
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
func (p *PkgResolver) GetPackageWithDependencies(pkgName string, existing map[string]*repository.RepositoryPackage) (pkg *repository.RepositoryPackage, dependencies []*repository.RepositoryPackage, conflicts []string, err error) {
	parents := make(map[string]bool)
	localExisting := make(map[string]*repository.RepositoryPackage)
	for k, v := range existing {
		localExisting[k] = v
	}

	pkgs, err := p.ResolvePackage(pkgName)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(pkgs) == 0 {
		return nil, nil, nil, fmt.Errorf("could not find package %s", pkgName)
	}
	pkg = pkgs[0]

	_, _, _, pin := resolvePackageNameVersionPin(pkgName)
	deps, conflicts, err := p.getPackageDependencies(pkg, pin, parents, localExisting)
	if err != nil {
		return
	}
	// eliminate duplication in dependencies
	added := map[string]*repository.RepositoryPackage{}
	for _, dep := range deps {
		if _, ok := added[dep.Name]; !ok {
			dependencies = append(dependencies, dep)
			added[dep.Name] = dep
		}
	}
	// are there any installIf dependencies?
	var (
		depPkgList []*repositoryPackage
		ok         bool
	)
	for dep, depPkg := range added {
		if depPkgList, ok = p.installIfMap[dep]; !ok {
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
				name, version, _, _ := resolvePackageNameVersionPin(subDep)
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
	return
}

// ResolvePackage given a single package name and optional version constraints, resolve to a list of packages
// that satisfy the constraint. The list will be sorted by version number, with the highest version first
// and decreasing from there. In general, the first one in the list is the best match. This function
// returns multiple in case you need to see all potential matches.
func (p *PkgResolver) ResolvePackage(pkgName string) (pkgs []*repository.RepositoryPackage, err error) {
	name, version, compare, pin := resolvePackageNameVersionPin(pkgName)
	pkgsWithVersions, ok := p.nameMap[name]
	var packages []*repositoryPackage
	if ok {
		// pkgsWithVersions contains a map of all versions of the package
		// get the one that most matches what was requested
		packages = filterPackages(pkgsWithVersions, withVersion(version, compare), withPreferPin(pin))
		if len(packages) == 0 {
			return nil, fmt.Errorf("could not find package %s in indexes: %w", pkgName, err)
		}
		sortPackages(packages, nil, nil, pin)
	} else {
		providers, ok := p.providesMap[name]
		if !ok || len(providers) == 0 {
			return nil, fmt.Errorf("could not find package, alias or a package that provides %s in indexes", pkgName)
		}
		// we are going to do this in reverse order
		sortPackages(providers, nil, nil, "")
		packages = providers
	}
	for _, pkg := range packages {
		pkgs = append(pkgs, pkg.RepositoryPackage)
	}
	return
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
func (p *PkgResolver) getPackageDependencies(pkg *repository.RepositoryPackage, allowPin string, parents map[string]bool, existing map[string]*repository.RepositoryPackage) (dependencies []*repository.RepositoryPackage, conflicts []string, err error) {
	// check if the package we are checking is one of our parents, avoid cyclical graphs
	if _, ok := parents[pkg.Name]; ok {
		return nil, nil, nil
	}
	myProvides := map[string]bool{}
	// see if we provide this
	for _, provide := range pkg.Provides {
		name, _, _, _ := resolvePackageNameVersionPin(provide)
		myProvides[provide] = true
		myProvides[name] = true
	}

	// each dependency has only one of two possibilities:
	// - !name     - "I cannot be installed along with the package <name>"
	// - name      - "I need package 'name'" -OR- "I need the package that provides <name>"
	for _, dep := range pkg.Dependencies {
		var (
			depPkg *repository.RepositoryPackage
			ok     bool
		)
		// if it was a conflict, just add it to the conflicts list and go to the next one
		if strings.HasPrefix(dep, "!") {
			conflicts = append(conflicts, dep[1:])
			continue
		}
		// this package might be pinned to a version
		name, version, compare, _ := resolvePackageNameVersionPin(dep)
		// see if we provide this
		if myProvides[name] || myProvides[dep] {
			// we provide this, so skip it
			continue
		}

		// first see if it is a name of a package
		depPkgWithVersions, ok := p.nameMap[name]
		if ok {
			// pkgsWithVersions contains a map of all versions of the package
			// get the one that most matches what was requested
			pkgs := filterPackages(depPkgWithVersions, withVersion(version, compare), withAllowPin(allowPin))
			if len(pkgs) == 0 {
				return nil, nil, fmt.Errorf("could not find package %s in indexes", dep)
			}
			sortPackages(pkgs, nil, existing, "")
			depPkg = pkgs[0].RepositoryPackage
		} else {
			// it was not the name of a package, see if some package provides this
			initialProviders, ok := p.providesMap[name]
			if !ok || len(initialProviders) == 0 {
				// no one provides it, return an error
				return nil, nil, fmt.Errorf("could not find package either named %s or that provides %s for %s", dep, dep, pkg.Name)
			}
			// before we sort the packages, figure out if we satisfy the dependency
			// also filter out invalid ones, i.e. ones that come from a pinned repository, but that pin is now allowed
			var (
				isSelf    bool
				providers []*repositoryPackage
			)
			for _, provider := range initialProviders {
				// if the provider package is pinned and does not match our allowed pin, skip it
				if provider.pinnedName != "" && provider.pinnedName != allowPin {
					continue
				}
				// if my package can provide this dependency, then already satisfied
				if provider.Name == pkg.Name {
					isSelf = true
					break
				}
				providers = append(providers, provider)
			}
			if isSelf {
				continue
			}
			// we are going to do this in reverse order
			sortPackages(providers, pkg, existing, "")
			depPkg = providers[0].RepositoryPackage
		}
		// and then recurse to its children
		// each child gets the parental chain, but should not affect any others,
		// so we duplicate the map for the child
		childParents := map[string]bool{}
		for k := range parents {
			childParents[k] = true
		}
		childParents[pkg.Name] = true
		subDeps, confs, err := p.getPackageDependencies(depPkg, allowPin, childParents, existing)
		if err != nil {
			return nil, nil, err
		}
		// first add the children, then the parent (depth-first)
		dependencies = append(dependencies, subDeps...)
		dependencies = append(dependencies, depPkg)
		conflicts = append(conflicts, confs...)
		for _, dep := range subDeps {
			existing[dep.Name] = dep
		}
	}
	return dependencies, conflicts, nil
}

// sortPackages sorts a slice of packages in descending order of preference, based on
// matching origin to a provided comparison package, whether or not one of the packages
// already is installed, the versions, and whether an origin already exists.
// The pin is for preference only; prefer a package that matches the pin over one that does not.
func sortPackages(pkgs []*repositoryPackage, compare *repository.RepositoryPackage, existing map[string]*repository.RepositoryPackage, pin string) {
	// get existing origins
	existingOrigins := map[string]bool{}
	for _, pkg := range existing {
		if pkg != nil && pkg.Origin != "" {
			existingOrigins[pkg.Origin] = true
		}
	}
	sort.Slice(pkgs, func(i, j int) bool {
		if compare != nil {
			// matching repository
			pkgRepo := compare.Repository().Uri
			iRepo := pkgs[i].Repository().Uri
			jRepo := pkgs[j].Repository().Uri
			if iRepo == pkgRepo && jRepo != pkgRepo {
				return true
			}
			if jRepo == pkgRepo && iRepo != pkgRepo {
				return false
			}
			// matching origin with compare
			pkgOrigin := compare.Origin
			iOrigin := pkgs[i].Origin
			jOrigin := pkgs[j].Origin
			if iOrigin == pkgOrigin && jOrigin != pkgOrigin {
				return true
			}
			if jOrigin == pkgOrigin && iOrigin != pkgOrigin {
				return false
			}
		}
		// see if one already is installed
		iMatched, iOk := existing[pkgs[i].Name]
		jMatched, jOk := existing[pkgs[j].Name]
		if iOk && !jOk && iMatched.Version == pkgs[i].Version {
			return true
		}
		if jOk && !iOk && jMatched.Version == pkgs[j].Version {
			return false
		}
		// see if an origin already is installed
		iOriginMatched := existingOrigins[pkgs[i].Origin]
		jOriginMatched := existingOrigins[pkgs[j].Origin]
		if iOriginMatched && !jOriginMatched {
			return true
		}
		if jOriginMatched && !iOriginMatched {
			return false
		}
		if pkgs[i].pinnedName == pin && pkgs[j].pinnedName != pin {
			return true
		}
		if pkgs[i].pinnedName != pin && pkgs[j].pinnedName == pin {
			return false
		}
		// check provider priority
		if pkgs[i].ProviderPriority != pkgs[j].ProviderPriority {
			return pkgs[i].ProviderPriority > pkgs[j].ProviderPriority
		}
		// both matched or both did not, so just compare versions
		// version priority
		iVersion, err := parseVersion(pkgs[i].Version)
		if err != nil {
			return false
		}
		jVersion, err := parseVersion(pkgs[j].Version)
		if err != nil {
			return false
		}
		versions := compareVersions(iVersion, jVersion)
		if versions != equal {
			return versions == greater
		}
		// if versions are equal, compare names
		return pkgs[i].Name < pkgs[j].Name
	})
}
