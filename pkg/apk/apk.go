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

import (
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"

	"chainguard.dev/apko/pkg/options"
	"chainguard.dev/apko/pkg/sbom"
)

// AdditionalTags is a helper function used in conjunction with the --package-version-tag flag
// If --package-version-tag is set to a package name (e.g. go), then this function
// returns a list of all images that should be published with the associated version of that package tagged (e.g. 1.18)
func AdditionalTags(fsys fs.FS, opts options.Options) ([]string, error) {
	if opts.PackageVersionTag == "" {
		return nil, nil
	}
	pkgs, err := sbom.ReadPackageIndex(fsys)
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
