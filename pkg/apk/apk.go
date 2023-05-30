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

package apk

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

import (
	"archive/tar"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"

	apkimpl "github.com/chainguard-dev/go-apk/pkg/apk"
	apkfs "github.com/chainguard-dev/go-apk/pkg/fs"
	"github.com/google/go-containerregistry/pkg/name"
	"gitlab.alpinelinux.org/alpine/go/repository"
	"golang.org/x/sync/errgroup"

	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/options"
	"chainguard.dev/apko/pkg/sbom"
)

type APK struct {
	impl    *apkimpl.APK
	fs      apkfs.FullFS
	Options options.Options
}

func New() (*APK, error) {
	return NewWithOptions(apkfs.DirFS("/"), options.Default)
}

func NewWithOptions(fsys apkfs.FullFS, o options.Options) (*APK, error) {
	opts := options.Default
	if o.Log == nil {
		o.Log = opts.Log
	}

	// apko does not execute the scripts, so they do not matter. This buys us flexibility
	// to run without root privileges, or even on non-Linux.
	apkImpl, err := apkimpl.New(
		apkimpl.WithFS(fsys),
		apkimpl.WithLogger(o.Logger()),
		apkimpl.WithArch(o.Arch.ToAPK()),
		apkimpl.WithIgnoreMknodErrors(true),
	)
	if err != nil {
		return nil, err
	}

	a := &APK{
		Options: o,
		impl:    apkImpl,
		fs:      fsys,
	}
	return a, nil
}

type Option func(*APK) error

// Initialize sets the image according to the image configuration,
// and does everything short of installing the packages.
func (a *APK) Initialize(ic types.ImageConfiguration) error {
	// initialize apk
	alpineVersions := parseOptionsFromRepositories(ic.Contents.Repositories)
	if err := a.impl.InitDB(alpineVersions...); err != nil {
		return fmt.Errorf("failed to initialize apk database: %w", err)
	}

	var eg errgroup.Group

	eg.Go(func() error {
		if err := a.impl.InitKeyring(ic.Contents.Keyring, a.Options.ExtraKeyFiles); err != nil {
			return fmt.Errorf("failed to initialize apk keyring: %w", err)
		}
		return nil
	})

	eg.Go(func() error {
		repos := append(ic.Contents.Repositories, a.Options.ExtraRepos...) // nolint:gocritic
		if err := a.impl.SetRepositories(repos); err != nil {
			return fmt.Errorf("failed to initialize apk repositories: %w", err)
		}
		return nil
	})

	eg.Go(func() error {
		packages := append(ic.Contents.Packages, a.Options.ExtraPackages...) //nolint:gocritic
		if err := a.impl.SetWorld(packages); err != nil {
			return fmt.Errorf("failed to initialize apk world: %w", err)
		}
		return nil
	})

	if err := eg.Wait(); err != nil {
		return err
	}

	return nil
}

// Install install packages. Only works if already initialized.
func (a *APK) Install() error {
	// sync reality with desired apk world
	return a.impl.FixateWorld(&a.Options.SourceDateEpoch)
}

// ResolvePackages gets list of packages that should be installed
func (a *APK) ResolvePackages() (toInstall []*repository.RepositoryPackage, conflicts []string, err error) {
	// sync reality with desired apk world
	return a.impl.ResolveWorld()
}

func (a *APK) GetInstalled() ([]*apkimpl.InstalledPackage, error) {
	return a.impl.GetInstalled()
}

// AdditionalTags is a helper function used in conjunction with the --package-version-tag flag
// If --package-version-tag is set to a package name (e.g. go), then this function
// returns a list of all images that should be published with the associated version of that package tagged (e.g. 1.18)
func AdditionalTags(fsys fs.FS, opts options.Options) ([]string, error) {
	if opts.PackageVersionTag == "" {
		return nil, nil
	}
	dbPath := "lib/apk/db/installed"
	pkgs, err := sbom.ReadPackageIndex(fsys, &sbom.DefaultOptions, dbPath)
	if err != nil {
		return nil, err
	}
	for _, pkg := range pkgs {
		if pkg.Name != opts.PackageVersionTag {
			continue
		}
		version := pkg.Version
		if version == "" {
			opts.Log.Warnf("Version for package %s is empty", pkg.Name)
			continue
		}
		if opts.TagSuffix != "" {
			version += opts.TagSuffix
		}
		opts.Log.Debugf("Found version, images will be tagged with %s", version)

		additionalTags, err := appendTag(opts, fmt.Sprintf("%s%s", opts.PackageVersionTagPrefix, version))
		if err != nil {
			return nil, err
		}

		if opts.PackageVersionTagStem && len(additionalTags) > 0 {
			opts.Log.Debugf("Adding stemmed version tags")
			stemmedTags, err := getStemmedVersionTags(opts, additionalTags[0], version)
			if err != nil {
				return nil, err
			}
			additionalTags = append(additionalTags, stemmedTags...)
		}

		opts.Log.Infof("Returning additional tags %v", additionalTags)
		return additionalTags, nil
	}
	opts.Log.Warnf("No version info found for package %s, skipping additional tagging", opts.PackageVersionTag)
	return nil, nil
}

func appendTag(opts options.Options, newTag string) ([]string, error) {
	newTags := make([]string, len(opts.Tags))
	for i, t := range opts.Tags {
		nt, err := replaceTag(t, newTag)
		if err != nil {
			return nil, err
		}
		newTags[i] = nt
	}
	return newTags, nil
}

func replaceTag(img, newTag string) (string, error) {
	ref, err := name.ParseReference(img)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s:%s", ref.Context(), newTag), nil
}

// TODO: use version parser from https://gitlab.alpinelinux.org/alpine/go/-/tree/master/version
func getStemmedVersionTags(opts options.Options, origRef string, version string) ([]string, error) {
	tags := []string{}
	re := regexp.MustCompile("[.]+")
	tmp := []string{}
	for _, part := range re.Split(version, -1) {
		tmp = append(tmp, part)
		additionalTag := strings.Join(tmp, ".")
		if additionalTag == version {
			tmp := strings.Split(version, "-")
			additionalTag = strings.Join(tmp[:len(tmp)-1], "-")
		}
		additionalTag, err := replaceTag(origRef,
			fmt.Sprintf("%s%s", opts.PackageVersionTagPrefix, additionalTag))
		if err != nil {
			return nil, err
		}
		tags = append(tags, additionalTag)
	}
	sort.Slice(tags, func(i, j int) bool {
		return tags[j] < tags[i]
	})
	return tags, nil
}

func (a *APK) ListInitFiles() []tar.Header {
	return a.impl.ListInitFiles()
}

var repoRE = regexp.MustCompile(`^http[s]?://.+\/alpine\/([^\/]+)\/[^\/]+$`)

func parseOptionsFromRepositories(repos []string) []string {
	var versions = make([]string, 0)
	for _, r := range repos {
		parts := repoRE.FindStringSubmatch(r)
		if len(parts) < 2 {
			continue
		}
		versions = append(versions, parts[1])
	}
	return versions
}
