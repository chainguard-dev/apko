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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gitlab.alpinelinux.org/alpine/go/repository"
	"go.lsp.dev/uri"
)

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

func (a *APKImplementation) GetRepositories() ([]string, error) {
	// get the repository URLs
	reposFile, err := a.fs.Open(reposFilePath)
	if err != nil {
		return nil, fmt.Errorf("could not open repositories file in %s at %s: %w", a.fs, reposFilePath, err)
	}
	defer reposFile.Close()
	reposData, err := io.ReadAll(reposFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read repositories file: %w", err)
	}
	return strings.Fields(string(reposData)), nil
}

// getRepositoryIndexes returns the indexes for the repositories in the specified root.
// The signatures for each index are verified unless ignoreSignatures is set to true.
func (a *APKImplementation) getRepositoryIndexes(ignoreSignatures bool) ([]*repository.RepositoryWithIndex, error) {
	var (
		indexes []*repository.RepositoryWithIndex
	)

	r := regexp.MustCompile(`^\.SIGN\.RSA\.(.*\.rsa\.pub)$`)

	// get the repository URLs
	repos, err := a.GetRepositories()
	if err != nil {
		return nil, err
	}

	archFile, err := a.fs.Open(archFilePath)
	if err != nil {
		return nil, fmt.Errorf("could not open arch file in %s at %s: %w", a.fs, archFile, err)
	}
	arch, err := io.ReadAll(archFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read arch file: %w", err)
	}
	for _, repoURI := range repos {
		repoBase := fmt.Sprintf("%s/%s", repoURI, arch)
		u := fmt.Sprintf("%s/%s", repoBase, indexFilename)

		// Normalize the repo as a URI, so that local paths
		// are translated into file:// URLs, allowing them to be parsed
		// into a url.URL{}.
		var (
			b     []byte
			asURI uri.URI
		)
		if strings.HasPrefix(u, "https://") {
			asURI, _ = uri.Parse(u)
		} else {
			asURI = uri.New(u)
		}
		asURL, err := url.Parse(string(asURI))
		if err != nil {
			return nil, fmt.Errorf("failed to parse repo as URI: %w", err)
		}

		switch asURL.Scheme {
		case "file":
			b, err = os.ReadFile(u)
			if err != nil {
				return nil, fmt.Errorf("failed to read repository %s: %w", u, err)
			}
		case "https":
			client := a.client
			if client == nil {
				client = &http.Client{}
			}
			res, err := client.Get(asURL.String()) // nolint:gosec // we know what we are doing here
			if err != nil {
				return nil, fmt.Errorf("unable to get repository index at %s: %w", u, err)
			}
			defer res.Body.Close()
			buf := bytes.NewBuffer(nil)
			if _, err := io.Copy(buf, res.Body); err != nil {
				return nil, fmt.Errorf("unable to read repository index at %s: %w", u, err)
			}
			b = buf.Bytes()
		default:
			return nil, fmt.Errorf("repository scheme %s not supported", asURL.Scheme)
		}

		// validate the signature
		if !ignoreSignatures {
			buf := bytes.NewReader(b)
			gzipReader, err := gzip.NewReader(buf)
			if err != nil {
				return nil, fmt.Errorf("unable to create gzip reader for repository index: %w", err)
			}
			// set multistream to false, so we can read each part separately;
			// the first part is the signature, the second is the index, which should be
			// verified.
			gzipReader.Multistream(false)
			defer gzipReader.Close()

			tarReader := tar.NewReader(gzipReader)

			// read the signature
			signatureFile, err := tarReader.Next()
			if err != nil {
				return nil, fmt.Errorf("failed to read signature from repository index: %w", err)
			}
			matches := r.FindStringSubmatch(signatureFile.Name)
			if len(matches) != 2 {
				return nil, fmt.Errorf("failed to find key name in signature file name: %s", signatureFile.Name)
			}
			signature, err := io.ReadAll(tarReader)
			if err != nil {
				return nil, fmt.Errorf("failed to read signature from repository index: %w", err)
			}
			// with multistream false, we should read the next one
			if _, err := tarReader.Next(); err != nil && !errors.Is(err, io.EOF) {
				return nil, fmt.Errorf("unexpected error reading from tgz: %w", err)
			}
			// we now have the signature bytes and name, get the contents of the rest;
			// this should be everything else in the raw gzip file as is.
			allBytes := len(b)
			unreadBytes := buf.Len()
			readBytes := allBytes - unreadBytes
			indexData := b[readBytes:]

			indexDigest, err := HashData(indexData)
			if err != nil {
				return nil, err
			}
			// now we can check the signature
			keyFilePath := filepath.Join(keysDirPath, matches[1])
			keyFile, err := a.fs.Open(keyFilePath)
			if err != nil {
				return nil, fmt.Errorf("could not open keyfile in %s at %s: %w", a.fs, keyFilePath, err)
			}
			keyData, err := io.ReadAll(keyFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read key file: %w", err)
			}
			if err := RSAVerifySHA1Digest(indexDigest, signature, keyData); err != nil {
				return nil, fmt.Errorf("signature did not match for keyfile %s: %w", keyFile, err)
			}

			// with a valid signature, convert it to an ApkIndex
			index, err := repository.IndexFromArchive(io.NopCloser(bytes.NewReader(b)))
			if err != nil {
				return nil, fmt.Errorf("unable to read convert repository index bytes to index struct at %s: %w", u, err)
			}
			repo := repository.Repository{Uri: repoBase}
			indexes = append(indexes, repo.WithIndex(index))
		}
	}
	return indexes, nil
}

// PkgResolver is a helper struct for resolving packages from a list of indexes.
// If the indexes change, you should generate a new pkgResolver.
type PkgResolver struct {
	indexes     []*repository.RepositoryWithIndex
	nameMap     map[string]map[string]*repository.RepositoryPackage
	providesMap map[string]string
}

// NewPkgResolver creates a new pkgResolver from a list of indexes.
func NewPkgResolver(indexes []*repository.RepositoryWithIndex) *PkgResolver {
	var (
		pkgNameMap     = map[string]map[string]*repository.RepositoryPackage{}
		pkgProvidesMap = map[string]string{}
	)
	p := &PkgResolver{
		indexes: indexes,
	}
	// create a map of every package by name and version to its RepositoryPackage
	for _, index := range indexes {
		for _, pkg := range index.Packages() {
			existingPkg, ok := pkgNameMap[pkg.Name]
			if !ok {
				existingPkg = map[string]*repository.RepositoryPackage{}
				pkgNameMap[pkg.Name] = existingPkg
			}
			existingPkg[pkg.Version] = pkg
		}
	}
	// create a map of every provided file to its package
	for pkgName, pkgVersions := range pkgNameMap {
		for _, pkg := range pkgVersions {
			for _, provide := range pkg.Provides {
				name, _, compare := resolvePackageNameVersion(provide)
				if _, ok := pkgProvidesMap[name]; !ok {
					pkgProvidesMap[name] = pkgName
				}
				if compare != versionNone {
					if _, ok := pkgProvidesMap[provide]; !ok {
						pkgProvidesMap[provide] = pkg.Name
					}
				}
			}
		}
	}
	p.nameMap = pkgNameMap
	p.providesMap = pkgProvidesMap
	return p
}

// GetPackagesWithDependencies get all of the dependencies for the given packages based on the
// indexes. Does not filter for installed already or not.
func (p *PkgResolver) GetPackagesWithDependencies(packages []string) (toInstall []*repository.RepositoryPackage, conflicts []string, err error) {
	var (
		dependenciesMap = map[string]bool{}
	)
	for _, pkgName := range packages {
		pkg, deps, confs, err := p.GetPackageWithDependencies(pkgName)
		if err != nil {
			return nil, nil, err
		}
		for _, dep := range deps {
			if _, ok := dependenciesMap[dep.Name]; !ok {
				toInstall = append(toInstall, dep)
				dependenciesMap[dep.Name] = true
			}
		}
		if _, ok := dependenciesMap[pkgName]; !ok {
			toInstall = append(toInstall, pkg)
			dependenciesMap[pkgName] = true
		}
		conflicts = append(conflicts, confs...)
	}

	conflicts = uniqify(conflicts)

	return toInstall, conflicts, nil
}

// GetPackageDependencies get all of the dependencies for a single package as well as looking
// up the package itself and resolving its version, based on the indexes.
func (p *PkgResolver) GetPackageWithDependencies(pkgName string) (pkg *repository.RepositoryPackage, dependencies []*repository.RepositoryPackage, conflicts []string, err error) {
	parents := make(map[string]bool)

	name, version, compare := resolvePackageNameVersion(pkgName)
	pkgsWithVersions, ok := p.nameMap[name]

	if !ok {
		trueName, ok := p.providesMap[name]
		if !ok {
			return nil, nil, nil, fmt.Errorf("could not find package, alias or a package that provides %s in indexes", pkgName)
		}
		pkgsWithVersions, ok = p.nameMap[trueName]
		if !ok {
			return nil, nil, nil, fmt.Errorf("looking for %s, found provided by %s, but could not find %s in indexes", pkgName, trueName, trueName)
		}
	}

	// pkgsWithVersions contains a map of all versions of the package
	// get the one that most matches what was requested
	versions := make([]string, 0, 10)
	for version := range pkgsWithVersions {
		versions = append(versions, version)
	}
	targetVersion := getBestVersion(versions, version, compare)
	if targetVersion == "" {
		return nil, nil, nil, fmt.Errorf("could not find package %s in indexes: %w", pkgName, err)
	}
	pkg = pkgsWithVersions[targetVersion]

	deps, conflicts, err := p.getPackageDependencies(pkg, parents)
	if err != nil {
		return
	}
	// eliminate duplication in dependencies
	dependenciesMap := map[string]bool{}
	for _, dep := range deps {
		if _, ok := dependenciesMap[dep.Name]; !ok {
			dependencies = append(dependencies, dep)
			dependenciesMap[dep.Name] = true
		}
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
func (p *PkgResolver) getPackageDependencies(pkg *repository.RepositoryPackage, parents map[string]bool) (dependencies []*repository.RepositoryPackage, conflicts []string, err error) {
	// check if the package we are checking is one of our parents, avoid cyclical graphs
	if _, ok := parents[pkg.Name]; ok {
		return nil, nil, nil
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
		if dep == "/bin/sh" {
			dep = "busybox"
		}
		// this package might be pinned to a version
		name, version, compare := resolvePackageNameVersion(dep)
		// first see if it is a name of a package
		depPkgWithVersions, ok := p.nameMap[name]
		if !ok {
			// it was not the name of a package, see if some package provides this
			provider, ok := p.providesMap[name]
			if !ok {
				// no one provides it, return an error
				return nil, nil, fmt.Errorf("could not find package either named %s or that provides %s for %s", dep, dep, pkg.Name)
			}
			depPkgWithVersions, ok = p.nameMap[provider]
			if !ok {
				return nil, nil, fmt.Errorf("required dependency %s is provided by package %s, which could not be found", name, provider)
			}
			name = provider
		}
		if name == pkg.Name {
			continue
		}
		// pkgsWithVersions contains a map of all versions of the package
		// get the one that most matches what was requested
		var versions []string
		for version := range depPkgWithVersions {
			versions = append(versions, version)
		}
		targetVersion := getBestVersion(versions, version, compare)
		if targetVersion == "" {
			return nil, nil, fmt.Errorf("could not find package %s in indexes: %w", dep, err)
		}
		depPkg = depPkgWithVersions[targetVersion]
		// and then recurse to its children
		// each child gets the parental chain, but should not affect any others,
		// so we duplicate the map for the child
		childParents := map[string]bool{}
		for k := range parents {
			childParents[k] = true
		}
		childParents[pkg.Name] = true
		subDeps, confs, err := p.getPackageDependencies(depPkg, childParents)
		if err != nil {
			return nil, nil, err
		}
		// first add the children, then the parent (depth-first)
		dependencies = append(dependencies, subDeps...)
		dependencies = append(dependencies, depPkg)
		conflicts = append(conflicts, confs...)
	}
	return dependencies, conflicts, nil
}
