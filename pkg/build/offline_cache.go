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

package build

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/chainguard-dev/clog"
	"k8s.io/apimachinery/pkg/util/sets"

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/apko/pkg/options"
)

// offlineKeysDir is the subdirectory of an offline cache holding the apk signing
// keys the configuration refers to, so that the cache is a self-contained input.
const offlineKeysDir = "keys"

// offlineOnly reports whether packages must come entirely from the offline
// cache, with no index read and no network request.
//
// --offline on its own keeps its older meaning of "make no network requests,
// satisfying the index from --cache-dir"; it is the combination with an offline
// cache that selects the index-free path.
func (bc *Context) offlineOnly() bool {
	return bc.o.Offline && bc.o.OfflineCacheDir != ""
}

// validateOffline rejects combinations that would otherwise silently pick one
// pinning mechanism and ignore the other.
func validateOffline(o *options.Options) error {
	if o.Offline && o.OfflineCacheDir != "" && o.Lockfile != "" {
		return fmt.Errorf("--lockfile and --offline with --offline-cache are two ways to pin the same thing; use one or the other (lockfile %s, offline cache %s)", o.Lockfile, o.OfflineCacheDir)
	}
	return nil
}

// offlineRepositories returns the repositories to search for packages, in the
// order they were configured. Unlike the resolving path, which sorts them, order
// is meaningful here: it decides which repository wins when more than one holds
// the same name and version.
func (bc *Context) offlineRepositories() ([]string, error) {
	var repos []string
	seen := sets.New[string]()
	for _, group := range [][]string{
		bc.ic.Contents.BuildRepositories,
		bc.ic.Contents.Repositories,
		bc.o.ExtraBuildRepos,
		bc.o.ExtraRepos,
	} {
		for _, repo := range group {
			repo = strings.TrimSuffix(repo, "/")
			if repo == "" || seen.Has(repo) {
				continue
			}
			seen.Insert(repo)
			if !apk.IsRemoteURL(repo) {
				return nil, fmt.Errorf("offline builds cannot use the local repository %q: only http(s) repositories are mirrored into an offline cache", repo)
			}
			repos = append(repos, repo)
		}
	}
	if len(repos) == 0 {
		return nil, errors.New("no repositories configured")
	}
	return repos, nil
}

// offlineInstallablePackages locates every package the configuration asks for in
// the offline cache.
//
// There is no index to resolve against, so the configuration's package list is
// taken as the complete set to install: it must name exact versions and must
// already include every transitive dependency.
func (bc *Context) offlineInstallablePackages(ctx context.Context) ([]apk.InstallablePackage, error) {
	log := clog.FromContext(ctx)

	if bc.baseimg != nil {
		return nil, errors.New("offline builds do not support a base image, whose packages are resolved from its own index")
	}

	if fi, err := os.Stat(bc.o.OfflineCacheDir); err != nil {
		return nil, fmt.Errorf("offline cache %s: %w", bc.o.OfflineCacheDir, err)
	} else if !fi.IsDir() {
		return nil, fmt.Errorf("offline cache %s is not a directory", bc.o.OfflineCacheDir)
	}

	repos, err := bc.offlineRepositories()
	if err != nil {
		return nil, err
	}

	arch := bc.Arch().ToAPK()

	// Order is preserved rather than sorted, because with no index there is no
	// dependency graph to install in the order of: packages are installed in the
	// order listed, and that order decides which package wins when two write the
	// same path. Listing a resolved closure in resolution order reproduces the
	// image an ordinary build would have produced.
	want := make([]string, 0, len(bc.ic.Contents.Packages)+len(bc.o.ExtraPackages))
	seen := sets.New[string]()
	for _, spec := range append(append([]string{}, bc.ic.Contents.Packages...), bc.o.ExtraPackages...) {
		if spec == "" || seen.Has(spec) {
			continue
		}
		seen.Insert(spec)
		want = append(want, spec)
	}

	constraints := make([]apk.ParsedConstraint, 0, len(want))
	var unpinned []string
	for _, spec := range want {
		c := apk.ResolvePackageNameVersionPin(spec)
		switch {
		case !c.IsExactVersion():
			unpinned = append(unpinned, spec)
		case c.Pin() != "":
			unpinned = append(unpinned, fmt.Sprintf("%s (repository pins are not supported offline)", spec))
		case strings.Contains(c.Name, ":"):
			// so:, cmd: and friends name something a package provides. Resolving
			// them needs the index's provides data.
			unpinned = append(unpinned, fmt.Sprintf("%s (virtual packages cannot be resolved offline)", spec))
		default:
			constraints = append(constraints, c)
		}
	}
	if len(unpinned) > 0 {
		return nil, fmt.Errorf("offline builds require every package to be pinned to an exact version (name=version); these are not:\n  %s", strings.Join(unpinned, "\n  "))
	}

	pkgs := make([]apk.InstallablePackage, 0, len(constraints))
	var problems []string
	for _, c := range constraints {
		pkg, err := bc.locateOfflinePackage(c, repos, arch)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		log.Debugf("offline cache: %s-%s from %s", c.Name, c.Version, pkg.URL())
		pkgs = append(pkgs, pkg)
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return nil, fmt.Errorf("%d package(s) could not be taken from the offline cache %s:\n  %s",
			len(problems), bc.o.OfflineCacheDir, strings.Join(problems, "\n  "))
	}

	return pkgs, nil
}

// locateOfflinePackage finds one pinned package in the offline cache, taking the
// first repository that holds it.
func (bc *Context) locateOfflinePackage(c apk.ParsedConstraint, repos []string, arch string) (apk.InstallablePackage, error) {
	tried := make([]string, 0, len(repos))
	for _, repo := range repos {
		path, err := apk.OfflineCachePath(bc.o.OfflineCacheDir, apk.APKURL(repo, arch, c.Name, c.Version))
		if err != nil {
			return nil, err
		}
		if _, err := os.Stat(path); err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return nil, fmt.Errorf("%s-%s: %w", c.Name, c.Version, err)
			}
			tried = append(tried, path)
			continue
		}
		checksum, err := apk.ReadOfflineChecksum(path)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil, fmt.Errorf("%s-%s: %s has no recorded checksum at %s; re-populate the cache rather than adding the apk by hand",
					c.Name, c.Version, path, apk.OfflineChecksumPath(path))
			}
			return nil, fmt.Errorf("%s-%s: %w", c.Name, c.Version, err)
		}
		return installablePackage{name: c.Name, url: path, checksum: checksum}, nil
	}
	return nil, fmt.Errorf("%s-%s: not in the cache; looked for %s", c.Name, c.Version, strings.Join(tried, ", "))
}

// offlineKeyring rewrites remote keyring entries to the copies held in the
// offline cache, since fetching them is not possible with the network closed.
// Local paths are left alone.
func (bc *Context) offlineKeyring(keyring []string) ([]string, error) {
	out := make([]string, 0, len(keyring))
	var missing []string
	for _, key := range keyring {
		if !apk.IsRemoteURL(key) {
			out = append(out, key)
			continue
		}
		path := filepath.Join(bc.o.OfflineCacheDir, offlineKeysDir, filepath.Base(key))
		if _, err := os.Stat(path); err != nil {
			missing = append(missing, fmt.Sprintf("%s (expected at %s)", key, path))
			continue
		}
		out = append(out, path)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("offline builds need the apk signing keys in the cache; these are missing:\n  %s", strings.Join(missing, "\n  "))
	}
	return out, nil
}

// saveOfflineKeyring copies the keys a build just installed into the offline
// cache, so that a later offline build has them without reaching the network.
// The keys have already been written into the image, so they are read back from
// there rather than fetched again.
func (bc *Context) saveOfflineKeyring(ctx context.Context, keyring []string) error {
	log := clog.FromContext(ctx)

	dir := filepath.Join(bc.o.OfflineCacheDir, offlineKeysDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	for _, key := range keyring {
		if !apk.IsRemoteURL(key) {
			continue
		}
		base := filepath.Base(key)
		data, err := fs.ReadFile(bc.fs, filepath.Join("etc", "apk", "keys", base))
		if err != nil {
			return fmt.Errorf("reading installed apk key %s: %w", base, err)
		}
		dst := filepath.Join(dir, base)
		// #nosec G306 -- apk keyring must be publicly readable
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			return fmt.Errorf("writing apk key to offline cache: %w", err)
		}
		log.Debugf("offline cache: saved key %s", dst)
	}
	return nil
}
