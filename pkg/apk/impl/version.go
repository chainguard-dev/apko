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
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// versionRegex how to parse versions.
// see https://github.com/alpinelinux/apk-tools/blob/50ab589e9a5a84592ee4c0ac5a49506bb6c552fc/src/version.c#
// for information on pinning, see https://wiki.alpinelinux.org/wiki/Alpine_Package_Keeper#Repository_pinning
// To quote:
//
//   After which you can "pin" dependencies to these tags using:
//
//      apk add stableapp newapp@edge bleedingapp@testing
//   Apk will now by default only use the untagged repositories, but adding a tag to specific package:
//
//   1. will prefer the repository with that tag for the named package, even if a later version of the package is available in another repository
//
//   2. allows pulling in dependencies for the tagged package from the tagged repository (though it prefers to use untagged repositories to satisfy dependencies if possible)

var (
	versionRegex     = regexp.MustCompile(`^([0-9]+)((\.[0-9]+)*)([a-z]?)((_alpha|_beta|_pre|_rc)([0-9]*))?((_cvs|_svn|_git|_hg|_p)([0-9]*))?((-r)([0-9]+))?$`)
	packageNameRegex = regexp.MustCompile(`^([^@=><~]+)(([=><]+)([^@]+))?(@([a-zA-Z0-9]+))?$`)
)

func init() {
	versionRegex.Longest()
	packageNameRegex.Longest()
}

type packageVersionPreModifier int
type packageVersionPostModifier int

// the order of these matters!
const (
	packageVersionPreModifierNone  packageVersionPreModifier = 0
	packageVersionPreModifierAlpha packageVersionPreModifier = 1
	packageVersionPreModifierBeta  packageVersionPreModifier = 2
	packageVersionPreModifierPre   packageVersionPreModifier = 3
	packageVersionPreModifierRC    packageVersionPreModifier = 4
	packageVersionPreModifierMax   packageVersionPreModifier = 1000
)
const (
	packageVersionPostModifierNone packageVersionPostModifier = 0
	packageVersionPostModifierCVS  packageVersionPostModifier = 1
	packageVersionPostModifierSVN  packageVersionPostModifier = 2
	packageVersionPostModifierGit  packageVersionPostModifier = 3
	packageVersionPostModifierHG   packageVersionPostModifier = 4
	packageVersionPostModifierP    packageVersionPostModifier = 5
	packageVersionPostModifierMax  packageVersionPostModifier = 1000
)

type packageVersion struct {
	numbers          []int
	letter           rune
	preSuffix        packageVersionPreModifier
	preSuffixNumber  int
	postSuffix       packageVersionPostModifier
	postSuffixNumber int
	revision         int
}

func parseVersion(version string) (packageVersion, error) {
	parts := versionRegex.FindAllStringSubmatch(version, -1)
	if len(parts) == 0 {
		return packageVersion{}, fmt.Errorf("invalid version %s, could not parse", version)
	}
	actuals := parts[0]
	numbers := make([]int, 0, 10)
	if len(actuals) != 14 {
		return packageVersion{}, fmt.Errorf("invalid version %s, could not find enough components", version)
	}

	// get the first version number
	num, err := strconv.Atoi(actuals[1])
	if err != nil {
		return packageVersion{}, fmt.Errorf("invalid version %s, first part is not number: %w", version, err)
	}
	numbers = append(numbers, num)

	// get any other version numbers
	if actuals[2] != "" {
		subparts := strings.Split(actuals[2], ".")
		for i, s := range subparts {
			if s == "" {
				continue
			}
			num, err := strconv.Atoi(s)
			if err != nil {
				return packageVersion{}, fmt.Errorf("invalid version %s, part %d is not number: %w", version, i, err)
			}
			numbers = append(numbers, num)
		}
	}
	var letter rune
	if len(actuals[4]) > 0 {
		letter = rune(actuals[4][0])
	}
	var preSuffix packageVersionPreModifier
	switch actuals[6] {
	case "_alpha":
		preSuffix = packageVersionPreModifierAlpha
	case "_beta":
		preSuffix = packageVersionPreModifierBeta
	case "_pre":
		preSuffix = packageVersionPreModifierPre
	case "_rc":
		preSuffix = packageVersionPreModifierRC
	case "":
		preSuffix = packageVersionPreModifierNone
	default:
		return packageVersion{}, fmt.Errorf("invalid version %s, pre-suffix %s is not valid", version, actuals[6])
	}
	var preSuffixNumber int
	if actuals[7] != "" {
		num, err := strconv.Atoi(actuals[7])
		if err != nil {
			return packageVersion{}, fmt.Errorf("invalid version %s, suffix %s number %s is not number: %w", version, actuals[6], actuals[7], err)
		}
		preSuffixNumber = num
	}

	var postSuffix packageVersionPostModifier
	switch actuals[9] {
	case "_cvs":
		postSuffix = packageVersionPostModifierCVS
	case "_svn":
		postSuffix = packageVersionPostModifierSVN
	case "_git":
		postSuffix = packageVersionPostModifierGit
	case "_hg":
		postSuffix = packageVersionPostModifierHG
	case "_p":
		postSuffix = packageVersionPostModifierP
	case "":
		postSuffix = packageVersionPostModifierNone
	default:
		return packageVersion{}, fmt.Errorf("invalid version %s, suffix %s is not valid", version, actuals[9])
	}
	var postSuffixNumber int
	if actuals[10] != "" {
		num, err := strconv.Atoi(actuals[10])
		if err != nil {
			return packageVersion{}, fmt.Errorf("invalid version %s, post-suffix %s number %s is not number: %w", version, actuals[9], actuals[10], err)
		}
		postSuffixNumber = num
	}

	var revision int
	if actuals[13] != "" {
		num, err := strconv.Atoi(actuals[13])
		if err != nil {
			return packageVersion{}, fmt.Errorf("invalid version %s, revision %s is not number: %w", version, actuals[13], err)
		}
		revision = num
	}
	return packageVersion{
		numbers:          numbers,
		letter:           letter,
		preSuffix:        preSuffix,
		preSuffixNumber:  preSuffixNumber,
		postSuffix:       postSuffix,
		postSuffixNumber: postSuffixNumber,
		revision:         revision,
	}, nil
}

type versionCompare int

const (
	greater versionCompare = 0
	equal   versionCompare = 1
	less    versionCompare = 2
)

// compare versions based on https://dev.gentoo.org/~ulm/pms/head/pms.html#x1-250003.2
func compareVersions(actual, required packageVersion) versionCompare {
	for i := 0; i < len(actual.numbers) && i < len(required.numbers); i++ {
		if actual.numbers[i] > required.numbers[i] {
			return greater
		}
		if actual.numbers[i] < required.numbers[i] {
			return less
		}
	}
	// if we made it here, the parts that were the same size are equal
	if len(actual.numbers) > len(required.numbers) {
		return greater
	}
	if len(actual.numbers) < len(required.numbers) {
		return less
	}
	// same length of numbers, same numbers
	// compare letters
	if actual.letter > required.letter {
		return greater
	}
	if actual.letter < required.letter {
		return less
	}
	// same letters
	// compare pre-suffixes
	// because None is 0 but the lowest priority to make it easy to have a sane default,
	// but lowest priority, we need some extra logic to handle
	actualPreSuffix, requiredPreSuffix := actual.preSuffix, required.preSuffix
	if actualPreSuffix == packageVersionPreModifierNone {
		actualPreSuffix = packageVersionPreModifierMax
	}
	if requiredPreSuffix == packageVersionPreModifierNone {
		requiredPreSuffix = packageVersionPreModifierMax
	}
	if actualPreSuffix > requiredPreSuffix {
		return greater
	}
	if actualPreSuffix < requiredPreSuffix {
		return less
	}
	// same pre-suffixes, compare pre-suffix numbers
	if actual.preSuffixNumber > required.preSuffixNumber {
		return greater
	}
	if actual.preSuffixNumber < required.preSuffixNumber {
		return less
	}
	// same pre-suffix numbers
	// compare post-suffixes
	// because None is 0 but the lowest priority to make it easy to have a sane default,
	// but lowest priority, we need some extra logic to handle
	actualPostSuffix, requiredPostSuffix := actual.postSuffix, required.postSuffix
	if actualPostSuffix == packageVersionPostModifierNone {
		actualPostSuffix = packageVersionPostModifierMax
	}
	if requiredPostSuffix == packageVersionPostModifierNone {
		requiredPostSuffix = packageVersionPostModifierMax
	}
	if actualPostSuffix > requiredPostSuffix {
		return greater
	}
	if actualPostSuffix < requiredPostSuffix {
		return less
	}
	// same post-suffixes, compare post-suffix numbers
	if actual.postSuffixNumber > required.postSuffixNumber {
		return greater
	}
	if actual.postSuffixNumber < required.postSuffixNumber {
		return less
	}
	// same post-suffix numbers
	// compare revisions
	if actual.revision > required.revision {
		return greater
	}
	if actual.revision < required.revision {
		return less
	}
	return equal
}

// includesVersion returns true if the actual version is a strict subset of the required version
func includesVersion(actual, required packageVersion) bool {
	// if more required numbers than actual numbers, than require is more specific,
	// so no match
	if len(actual.numbers) < len(required.numbers) {
		return false
	}
	for i := 0; i < len(required.numbers); i++ {
		if actual.numbers[i] != required.numbers[i] {
			return false
		}
	}
	// if length is the same, check the rest of it; if actual is longer, it's ok
	if len(actual.numbers) > len(required.numbers) {
		return true
	}
	// was there a required letter?
	if required.letter != 0 && actual.letter != required.letter {
		return false
	}

	// was there pre-suffix
	if required.preSuffix != packageVersionPreModifierNone && actual.preSuffix != required.preSuffix {
		return false
	}

	// was there pre-suffix number
	if required.preSuffixNumber != 0 && actual.preSuffixNumber != required.preSuffixNumber {
		return false
	}

	// was there post-suffix
	if required.postSuffix != packageVersionPostModifierNone && actual.postSuffix != required.postSuffix {
		return false
	}
	if required.postSuffixNumber != 0 && actual.postSuffixNumber != required.postSuffixNumber {
		return false
	}

	// compare revisions
	if required.revision != 0 && actual.revision != required.revision {
		return false
	}
	return true
}

type versionDependency int

const (
	versionNone versionDependency = iota
	versionEqual
	versionGreater
	versionLess
	versionGreaterEqual
	versionLessEqual
	versionTilde
)

func (v versionDependency) satisfies(actualVersion, requiredVersion packageVersion) bool {
	if v == versionTilde {
		return includesVersion(actualVersion, requiredVersion)
	}
	c := compareVersions(actualVersion, requiredVersion)
	switch v {
	case versionNone:
		return true
	case versionEqual:
		return c == equal
	case versionGreater:
		return c == greater
	case versionLess:
		return c == less
	case versionGreaterEqual:
		return c == greater || c == equal
	case versionLessEqual:
		return c == less || c == equal
	default:
		return false
	}
}

func resolvePackageNameVersionPin(pkgName string) (name, version string, dep versionDependency, pin string) {
	parts := packageNameRegex.FindAllStringSubmatch(pkgName, -1)
	if len(parts) == 0 || len(parts[0]) < 2 {
		return pkgName, version, versionNone, pin
	}
	// layout: [full match, name, =version, =|>|<, version, @pin, pin]
	name = parts[0][1]
	matcher := parts[0][3]
	version = parts[0][4]
	pin = parts[0][6]
	if matcher != "" {
		// we have an equal
		switch matcher {
		case "=":
			dep = versionEqual
		case ">":
			dep = versionGreater
		case "<":
			dep = versionLess
		case ">=":
			dep = versionGreaterEqual
		case "<=":
			dep = versionLessEqual
		case "~":
			dep = versionTilde
		default:
			dep = versionNone
		}
	}
	return
}

type filterOptions struct {
	allowPin  string
	preferPin string
	version   string
	compare   versionDependency
}

type filterOption func(*filterOptions)

func withAllowPin(pin string) filterOption {
	return func(o *filterOptions) {
		o.allowPin = pin
	}
}
func withPreferPin(pin string) filterOption {
	return func(o *filterOptions) {
		o.preferPin = pin
	}
}
func withVersion(version string, compare versionDependency) filterOption {
	return func(o *filterOptions) {
		o.version = version
		o.compare = compare
	}
}

func filterPackages(pkgs []*repositoryPackage, opts ...filterOption) []*repositoryPackage {
	o := &filterOptions{
		compare: versionNone,
	}
	for _, opt := range opts {
		opt(o)
	}

	// go through all potential versions, save the ones that meet the constraints,
	// then take the highest
	var passed []*repositoryPackage
	for _, p := range pkgs {
		// do we allow this package?

		// if it has a pinned name, and it is not preferred or allowed, we reject it immediately
		if p.pinnedName != "" && p.pinnedName != o.allowPin && p.pinnedName != o.preferPin {
			continue
		}
		if o.compare == versionNone {
			passed = append(passed, p)
			continue
		}

		requiredVersion, err := parseVersion(o.version)
		// if the required version is invalid, we can't compare, so we return no matches
		if err != nil {
			return nil
		}

		actualVersion, err := parseVersion(p.Version)
		// skip invalid ones
		if err != nil {
			continue
		}

		if o.compare.satisfies(actualVersion, requiredVersion) {
			passed = append(passed, p)
			continue
		}

		for _, prov := range p.Provides {
			_, version, _, _ := resolvePackageNameVersionPin(prov)
			if version == "" {
				continue
			}

			actualVersion, err = parseVersion(version)
			// again, we skip invalid ones
			if err != nil {
				continue
			}

			if o.compare.satisfies(actualVersion, requiredVersion) {
				passed = append(passed, p)
				break
			}
		}
	}
	return passed
}
