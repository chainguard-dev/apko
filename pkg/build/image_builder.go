// Copyright 2022 Chainguard, Inc.
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
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hashicorp/go-multierror"
	"gitlab.alpinelinux.org/alpine/go/pkg/repository"
	"golang.org/x/sync/errgroup"
)

// Builds the image in Context.WorkDir.
func (bc *Context) BuildImage() error {
	log.Printf("doing pre-flight checks")
	if err := bc.ImageConfiguration.Validate(); err != nil {
		return fmt.Errorf("failed to validate configuration: %w", err)
	}

	log.Printf("building image fileystem in %s", bc.WorkDir)

	// initialize apk
	if err := bc.InitApkDB(); err != nil {
		return fmt.Errorf("failed to initialize apk database: %w", err)
	}

	var eg errgroup.Group

	eg.Go(func() error {
		if err := bc.InitApkKeyring(); err != nil {
			return fmt.Errorf("failed to initialize apk keyring: %w", err)
		}
		return nil
	})

	eg.Go(func() error {
		if err := bc.InitApkRepositories(); err != nil {
			return fmt.Errorf("failed to initialize apk repositories: %w", err)
		}
		return nil
	})

	eg.Go(func() error {
		if err := bc.InitApkWorld(); err != nil {
			return fmt.Errorf("failed to initialize apk world: %w", err)
		}
		return nil
	})

	if err := eg.Wait(); err != nil {
		return err
	}

	// sync reality with desired apk world
	if err := bc.FixateApkWorld(); err != nil {
		return fmt.Errorf("failed to fixate apk world: %w", err)
	}

	eg.Go(func() error {
		if err := bc.normalizeApkScriptsTar(); err != nil {
			return fmt.Errorf("failed to normalize scripts.tar: %w", err)
		}
		return nil
	})

	eg.Go(func() error {
		if err := bc.MutateAccounts(); err != nil {
			return fmt.Errorf("failed to mutate accounts: %w", err)
		}
		return nil
	})

	if err := eg.Wait(); err != nil {
		return err
	}

	if err := bc.runAssertions(); err != nil {
		return err
	}

	// maybe install busybox symlinks
	if err := bc.InstallBusyboxSymlinks(); err != nil {
		return fmt.Errorf("failed to install busybox symlinks: %w", err)
	}

	// write service supervision tree
	if err := bc.WriteSupervisionTree(); err != nil {
		return fmt.Errorf("failed to write supervision tree: %w", err)
	}

	log.Printf("finished building filesystem in %s", bc.WorkDir)
	return nil
}

// TODO: integrate this with BuildImage
func (bc *Context) BuildMultilayerImage() ([]string, error) {
	sortedPkgs, err := bc.GetSortedPkgs()
	if err != nil {
		return nil, fmt.Errorf("failed to get sorted packages: %w", err)
	}
	// TODO: remove debug logs
	log.Print("sorted packages:")
	for _, pkg := range sortedPkgs {
		log.Print(pkg.Name)
	}

	// TODO: parallelize this, just be careful to retain the same order
	var layerTarGZs []string
	for _, pkg := range sortedPkgs {
		layerTarGZ, err := bc.FetchPkg(pkg)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch package %s: %w", pkg.Filename(), err)
		}
		layerTarGZs = append(layerTarGZs, layerTarGZ)
	}

	// TODO: assertions, mutate accounts, supervision tree, SBOM, busybox symlinks, etc.

	log.Printf("finished fetching packages in %s", bc.WorkDir)
	return layerTarGZs, nil
}

func (bc *Context) runAssertions() error {
	var eg multierror.Group

	for _, a := range bc.Assertions {
		a := a
		eg.Go(func() error { return a(bc) })
	}

	return eg.Wait().ErrorOrNil()
}

// Installs the BusyBox symlinks, if appropriate.
func (bc *Context) InstallBusyboxSymlinks() error {
	path := filepath.Join(bc.WorkDir, "bin", "busybox")

	_, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}

		return err
	}

	// use proot + qemu to run the installer
	if err := bc.ExecuteChroot("/bin/busybox", "--install", "-s"); err != nil {
		return fmt.Errorf("failed to install busybox symlinks: %w", err)
	}

	return nil
}

// TODO: remove .PKGINFO and .SIGN* keyfiles from the tarball
// TODO: how do we use the keyfiles here?
func (bc *Context) FetchPkg(pkg *repository.RepositoryPackage) (string, error) {
	destPath := filepath.Join(bc.WorkDir, pkg.Filename())
	f, err := os.OpenFile(destPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", fmt.Errorf("failed to open %s: %w", destPath, err)
	}
	defer f.Close()

	pkgURL, err := url.Parse(pkg.Url())
	if err != nil {
		return "", fmt.Errorf("failed to parse package URL: %w", err)
	}
	resp, err := http.Get(pkgURL.String())
	if err != nil {
		return "", fmt.Errorf("failed to fetch package: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		resp.Body.Close()
		return "", fmt.Errorf("failed to fetch package %s: %s", pkgURL, resp.Status)
	}

	// TODO: consider CopyBuffer instead
	_, err = io.Copy(f, resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to write %s: %w", destPath, err)
	}
	return destPath, nil
}

// TODO: make this work when user requests pinned version of package
// TODO: What is supposed to happen when there are multiple alternatives for a package (i.e. libudev).
// TODO: Is checking each repository in the order provided and using the first one the package is found in correct?
// TODO: this probably uses a ton of memory holding all packages for each repo in memory, see if there's a way to lazy load info from disk/remote
func (bc *Context) GetSortedPkgs() ([]*repository.RepositoryPackage, error) {
	pkgs := make(map[string][]*repository.RepositoryPackage)
	for _, repoUri := range bc.ImageConfiguration.Contents.Repositories {
		// TODO: this seems hacky?
		repoUri = repoUri + "/" + bc.Arch.ToAPK()
		repo := &repository.Repository{
			Uri: repoUri,
		}

		// TODO: handle non-http[s] uris?
		indexUri := repo.IndexUri()
		asURL, err := url.Parse(indexUri)
		if err != nil {
			return nil, fmt.Errorf("failed to parse repository index uri: %w", err)
		}
		resp, err := http.Get(asURL.String())
		if err != nil {
			return nil, fmt.Errorf("failed to fetch repository index %q: %w", asURL.String(), err)
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to fetch repository index: %q %s", asURL.String(), resp.Status)
		}
		apkIndex, err := repository.IndexFromArchive(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to parse repository index: %w", err)
		}

		for _, pkg := range repo.WithIndex(apkIndex).Packages() {
			pkgs[pkg.Name] = append(pkgs[pkg.Name], pkg)
			// TODO: this is all really really hacky...
			versioned := fmt.Sprintf("%s=%s", pkg.Name, pkg.Version)
			pkgs[versioned] = append(pkgs[versioned], pkg)
			for _, provided := range pkg.Provides {
				pkgs[provided] = append(pkgs[provided], pkg)
				unversioned := strings.Split(provided, "=")[0]
				pkgs[unversioned] = append(pkgs[unversioned], pkg)
			}
		}
	}

	getPkg := func(name string) (*repository.RepositoryPackage, error) {
		pkgs := pkgs[name]
		if len(pkgs) == 0 {
			return nil, fmt.Errorf("failed to find package %s", name)
		}
		return pkgs[0], nil
	}

	var targetPkgs []*repository.RepositoryPackage
	for _, name := range bc.ImageConfiguration.Contents.Packages {
		pkg, err := getPkg(name)
		if err != nil {
			return nil, err
		}
		targetPkgs = append(targetPkgs, pkg)
	}

	return tsort(targetPkgs, func(pkg *repository.RepositoryPackage) ([]*repository.RepositoryPackage, error) {
		// TODO: not sure what's going on here.. alpine-baselayout-data has a dep on itself... hacky workaround for now
		if strings.HasPrefix(pkg.Name, "alpine-baselayout-data") {
			return nil, nil
		}

		var deps []*repository.RepositoryPackage
		for _, depName := range pkg.Dependencies {
			depPkg, err := getPkg(depName)
			if err != nil {
				return nil, err
			}
			deps = append(deps, depPkg)
		}
		return deps, nil
	})
}

func tsort(targetPkgs []*repository.RepositoryPackage, getDeps func(pkg *repository.RepositoryPackage) ([]*repository.RepositoryPackage, error)) ([]*repository.RepositoryPackage, error) {
	type pkgVtx struct {
		pkg     *repository.RepositoryPackage
		deps    map[*pkgVtx]struct{}
		revdeps map[*pkgVtx]struct{}
		added   bool
	}

	pkgs := make(map[string]*pkgVtx)
	var ready []*pkgVtx
	var add func(*repository.RepositoryPackage, *repository.RepositoryPackage) error
	add = func(pkg, rdep *repository.RepositoryPackage) error {
		vtx, ok := pkgs[pkg.Name]
		if !ok {
			vtx = &pkgVtx{
				pkg:     pkg,
				deps:    make(map[*pkgVtx]struct{}),
				revdeps: make(map[*pkgVtx]struct{}),
			}
			pkgs[pkg.Name] = vtx
		}
		if rdep != nil {
			if rvtx, ok := pkgs[rdep.Name]; ok {
				vtx.revdeps[rvtx] = struct{}{}
				rvtx.deps[vtx] = struct{}{}
			}
		}

		if vtx.added {
			return nil
		}
		vtx.added = true
		deps, err := getDeps(pkg)
		if err != nil {
			return err
		}

		if len(deps) == 0 {
			ready = append(ready, vtx)
		}
		for _, dep := range deps {
			if err := add(dep, pkg); err != nil {
				return err
			}
		}
		return nil
	}

	for _, pkg := range targetPkgs {
		if err := add(pkg, nil); err != nil {
			return nil, err
		}
	}

	var sorted []*repository.RepositoryPackage
	for len(ready) > 0 {
		// make the order within a topological level deterministic, helps container runtimes
		// deduplicate when unpacking snapshots
		// TODO: double check the above actually is true
		sort.Slice(ready, func(i, j int) bool {
			return ready[i].pkg.Name < ready[j].pkg.Name
		})
		var next []*pkgVtx
		for _, vtx := range ready {
			sorted = append(sorted, vtx.pkg)
			for dep := range vtx.revdeps {
				delete(dep.deps, vtx)
				if len(dep.deps) == 0 {
					next = append(next, dep)
				}
			}
			delete(pkgs, vtx.pkg.Name)
		}
		ready = next
	}
	if len(pkgs) > 0 {
		return nil, fmt.Errorf("cycle detected") // TODO: more helpful error
	}
	return sorted, nil
}
