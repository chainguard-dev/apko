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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseVersion(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		tests := []struct {
			version  string
			expected packageVersion
		}{
			// various legitimate ones
			{"1", packageVersion{numbers: []int{1}, preSuffix: packageVersionPreModifierNone, postSuffix: packageVersionPostModifierNone, revision: 0}},
			{"1.1", packageVersion{numbers: []int{1, 1}, preSuffix: packageVersionPreModifierNone, postSuffix: packageVersionPostModifierNone, revision: 0}},
			{"1.1.1", packageVersion{numbers: []int{1, 1, 1}, preSuffix: packageVersionPreModifierNone, postSuffix: packageVersionPostModifierNone, revision: 0}},
			{"1a", packageVersion{numbers: []int{1}, letter: 'a', preSuffix: packageVersionPreModifierNone, postSuffix: packageVersionPostModifierNone, revision: 0}},
			{"1.1a", packageVersion{numbers: []int{1, 1}, letter: 'a', preSuffix: packageVersionPreModifierNone, postSuffix: packageVersionPostModifierNone, revision: 0}},
			{"1.1.1a", packageVersion{numbers: []int{1, 1, 1}, letter: 'a', preSuffix: packageVersionPreModifierNone, postSuffix: packageVersionPostModifierNone, revision: 0}},
			{"1_alpha", packageVersion{numbers: []int{1}, preSuffix: packageVersionPreModifierAlpha, postSuffix: packageVersionPostModifierNone, revision: 0}},
			{"1_beta", packageVersion{numbers: []int{1}, preSuffix: packageVersionPreModifierBeta, postSuffix: packageVersionPostModifierNone, revision: 0}},
			{"1_alpha1", packageVersion{numbers: []int{1}, preSuffix: packageVersionPreModifierAlpha, preSuffixNumber: 1, postSuffix: packageVersionPostModifierNone, revision: 0}},
			{"1_alpha2", packageVersion{numbers: []int{1}, preSuffix: packageVersionPreModifierAlpha, preSuffixNumber: 2, postSuffix: packageVersionPostModifierNone, revision: 0}},
			{"1.1_alpha", packageVersion{numbers: []int{1, 1}, preSuffix: packageVersionPreModifierAlpha, postSuffix: packageVersionPostModifierNone, revision: 0}},
			{"1.1.1_alpha", packageVersion{numbers: []int{1, 1, 1}, preSuffix: packageVersionPreModifierAlpha, postSuffix: packageVersionPostModifierNone, revision: 0}},
			{"1.1_alpha1", packageVersion{numbers: []int{1, 1}, preSuffix: packageVersionPreModifierAlpha, preSuffixNumber: 1, postSuffix: packageVersionPostModifierNone, revision: 0}},
			{"1a_alpha1", packageVersion{numbers: []int{1}, letter: 'a', preSuffix: packageVersionPreModifierAlpha, preSuffixNumber: 1, postSuffix: packageVersionPostModifierNone, revision: 0}},
			{"1a_alpha2", packageVersion{numbers: []int{1}, letter: 'a', preSuffix: packageVersionPreModifierAlpha, preSuffixNumber: 2, postSuffix: packageVersionPostModifierNone, revision: 0}},
			{"1.1b_alpha", packageVersion{numbers: []int{1, 1}, letter: 'b', preSuffix: packageVersionPreModifierAlpha, postSuffix: packageVersionPostModifierNone, revision: 0}},
			{"1.1.1c_alpha", packageVersion{numbers: []int{1, 1, 1}, letter: 'c', preSuffix: packageVersionPreModifierAlpha, postSuffix: packageVersionPostModifierNone, revision: 0}},
			{"1.1r_alpha1", packageVersion{numbers: []int{1, 1}, preSuffix: packageVersionPreModifierAlpha, preSuffixNumber: 1, letter: 'r', postSuffix: packageVersionPostModifierNone, revision: 0}},
			{"1.1.1s_alpha2", packageVersion{numbers: []int{1, 1, 1}, preSuffix: packageVersionPreModifierAlpha, preSuffixNumber: 2, letter: 's', postSuffix: packageVersionPostModifierNone, revision: 0}},
			{"1-r2", packageVersion{numbers: []int{1}, preSuffix: packageVersionPreModifierNone, postSuffix: packageVersionPostModifierNone, revision: 2}},
			{"1.1-r2", packageVersion{numbers: []int{1, 1}, preSuffix: packageVersionPreModifierNone, postSuffix: packageVersionPostModifierNone, revision: 2}},
			{"1.1.1-r2", packageVersion{numbers: []int{1, 1, 1}, preSuffix: packageVersionPreModifierNone, postSuffix: packageVersionPostModifierNone, revision: 2}},
			{"1a-r2", packageVersion{numbers: []int{1}, letter: 'a', preSuffix: packageVersionPreModifierNone, postSuffix: packageVersionPostModifierNone, revision: 2}},
			{"1.1a-r2", packageVersion{numbers: []int{1, 1}, letter: 'a', preSuffix: packageVersionPreModifierNone, postSuffix: packageVersionPostModifierNone, revision: 2}},
			{"1.1.1a-r2", packageVersion{numbers: []int{1, 1, 1}, letter: 'a', preSuffix: packageVersionPreModifierNone, postSuffix: packageVersionPostModifierNone, revision: 2}},
			{"1_alpha-r2", packageVersion{numbers: []int{1}, preSuffix: packageVersionPreModifierAlpha, postSuffix: packageVersionPostModifierNone, revision: 2}},
			{"1_beta-r2", packageVersion{numbers: []int{1}, preSuffix: packageVersionPreModifierBeta, postSuffix: packageVersionPostModifierNone, revision: 2}},
			{"1_alpha1-r2", packageVersion{numbers: []int{1}, preSuffix: packageVersionPreModifierAlpha, preSuffixNumber: 1, postSuffix: packageVersionPostModifierNone, revision: 2}},
			{"1_alpha2-r2", packageVersion{numbers: []int{1}, preSuffix: packageVersionPreModifierAlpha, preSuffixNumber: 2, postSuffix: packageVersionPostModifierNone, revision: 2}},
			{"1.1_alpha-r2", packageVersion{numbers: []int{1, 1}, preSuffix: packageVersionPreModifierAlpha, postSuffix: packageVersionPostModifierNone, revision: 2}},
			{"1.1.1_alpha-r2", packageVersion{numbers: []int{1, 1, 1}, preSuffix: packageVersionPreModifierAlpha, postSuffix: packageVersionPostModifierNone, revision: 2}},
			{"1.1_alpha1-r2", packageVersion{numbers: []int{1, 1}, preSuffix: packageVersionPreModifierAlpha, preSuffixNumber: 1, postSuffix: packageVersionPostModifierNone, revision: 2}},
			{"1.1.1_alpha2-r2", packageVersion{numbers: []int{1, 1, 1}, preSuffix: packageVersionPreModifierAlpha, preSuffixNumber: 2, postSuffix: packageVersionPostModifierNone, revision: 2}},
			{"1a_alpha1-r2", packageVersion{numbers: []int{1}, letter: 'a', preSuffix: packageVersionPreModifierAlpha, preSuffixNumber: 1, postSuffix: packageVersionPostModifierNone, revision: 2}},
			{"1a_alpha2-r2", packageVersion{numbers: []int{1}, letter: 'a', preSuffix: packageVersionPreModifierAlpha, preSuffixNumber: 2, postSuffix: packageVersionPostModifierNone, revision: 2}},
			{"1.1b_alpha-r2", packageVersion{numbers: []int{1, 1}, letter: 'b', preSuffix: packageVersionPreModifierAlpha, postSuffix: packageVersionPostModifierNone, revision: 2}},
			{"1.1.1c_alpha-r2", packageVersion{numbers: []int{1, 1, 1}, letter: 'c', preSuffix: packageVersionPreModifierAlpha, postSuffix: packageVersionPostModifierNone, revision: 2}},
			{"1.1r_alpha1-r2", packageVersion{numbers: []int{1, 1}, preSuffix: packageVersionPreModifierAlpha, preSuffixNumber: 1, letter: 'r', postSuffix: packageVersionPostModifierNone, revision: 2}},
			{"1.1.1s_alpha2-r2", packageVersion{numbers: []int{1, 1, 1}, preSuffix: packageVersionPreModifierAlpha, preSuffixNumber: 2, letter: 's', postSuffix: packageVersionPostModifierNone, revision: 2}},
			{"1.1.1-r2", packageVersion{numbers: []int{1, 1, 1}, preSuffix: packageVersionPreModifierNone, postSuffix: packageVersionPostModifierNone, revision: 2}},
			{"1.1.1-r29", packageVersion{numbers: []int{1, 1, 1}, preSuffix: packageVersionPreModifierNone, postSuffix: packageVersionPostModifierNone, revision: 29}},
		}
		for _, tt := range tests {
			actual, err := parseVersion(tt.version)
			require.NoError(t, err, "%q unexpected error", tt.version)
			require.Equal(t, tt.expected, actual, "%q expected %v, got %v", tt.version, tt.expected, actual)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		tests := []string{
			// various illegitimate ones
			"a.1.2",
			"1.a.2",
			"1_illegal",
			"1_illegal",
			"1.1.1-rQ",
		}
		for _, version := range tests {
			_, err := parseVersion(version)
			require.Error(t, err, "%q mismatched error", version)
		}
	})
}

func TestResolveVersion(t *testing.T) {
	versions := []string{"1.2.3-r0", "1.3.6-r0", "1.2.8-r0", "1.7.1-r0", "1.7.1-r1", "2.0.6-r0"}
	tests := []struct {
		version     string
		compare     versionDependency
		want        string
		description string
	}{
		{"1.2.3-r0", versionEqual, "1.2.3-r0", "exact version match"},
		{"1.2.3-r10000", versionEqual, "", "exact version no match"},
		{"2.0.0", versionGreater, "2.0.6-r0", "greater than version match"},
		{"2.0.0", versionGreaterEqual, "2.0.6-r0", "greater than or equal to version match"},
		{"3.0.0", versionGreaterEqual, "", "greater than or equal to version no match"},
		{"", versionNone, "2.0.6-r0", "no requirement should get highest version"},
	}
	for _, tt := range tests {
		found := getBestVersion(versions, tt.version, tt.compare)
		require.Equal(t, found, tt.want, "version resolver gets correct version")
	}
}
