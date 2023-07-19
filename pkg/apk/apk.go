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
	"regexp"
	"sort"
	"strings"

	apkimpl "github.com/chainguard-dev/go-apk/pkg/apk"
	"github.com/google/go-containerregistry/pkg/name"

	"chainguard.dev/apko/pkg/log"
)

// AdditionalTags is a helper function used in conjunction with the --package-version-tag flag
// If --package-version-tag is set to a package name (e.g. go), then this function
// returns a list of all images that should be published with the associated version of that package tagged (e.g. 1.18)
func AdditionalTags(pkgs []*apkimpl.InstalledPackage, logger log.Logger, tags []string, packageVersionTag, packageVersionTagPrefix, tagSuffix string, packageVersionTagStem bool) ([]string, error) {
	if packageVersionTag == "" {
		return nil, nil
	}
	for _, pkg := range pkgs {
		if pkg.Name != packageVersionTag {
			continue
		}
		version := pkg.Version
		if version == "" {
			logger.Warnf("Version for package %s is empty", pkg.Name)
			continue
		}
		logger.Debugf("Found version, images will be tagged with %s", version)

		additionalTags, err := appendTag(tags, fmt.Sprintf("%s%s", packageVersionTagPrefix, version))
		if err != nil {
			return nil, err
		}

		if packageVersionTagStem && len(additionalTags) > 0 {
			logger.Debugf("Adding stemmed version tags")
			stemmedTags, err := getStemmedVersionTags(packageVersionTagPrefix, additionalTags[0], version)
			if err != nil {
				return nil, err
			}
			additionalTags = append(additionalTags, stemmedTags...)
		}
		finalTags := additionalTags
		if tagSuffix != "" {
			finalTags = []string{}
			for _, tag := range additionalTags {
				finalTags = append(finalTags, fmt.Sprintf("%s%s", tag, tagSuffix))
			}
		}

		logger.Infof("Returning additional tags %v", finalTags)
		return finalTags, nil
	}
	logger.Warnf("No version info found for package %s, skipping additional tagging", packageVersionTag)
	return nil, nil
}

func appendTag(tags []string, newTag string) ([]string, error) {
	newTags := make([]string, len(tags))
	for i, t := range tags {
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
func getStemmedVersionTags(packageVersionTagPrefix string, origRef string, version string) ([]string, error) {
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
			fmt.Sprintf("%s%s", packageVersionTagPrefix, additionalTag))
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
