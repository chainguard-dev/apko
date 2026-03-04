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

package keyring

import (
	"strings"
	"time"
)

type Releases struct {
	Architectures   []string        `json:"architectures"`
	LatestStable    string          `json:"latest_stable"`
	ReleaseBranches []ReleaseBranch `json:"release_branches"`
}

type ReleaseBranch struct {
	Arches        []string              `json:"arches"`
	GitBranch     string                `json:"git_branch"`
	Keys          map[string][]RepoKeys `json:"keys"`
	ReleaseBranch string                `json:"rel_branch"`
	Repos         []Repo                `json:"repos"`
}

type Repo struct {
	Name string   `json:"name"`
	EOL  DateTime `json:"eol_date"`
}

type RepoKeys struct {
	URL        string   `json:"url"`
	Deprecated DateTime `json:"deprecated_since"`
}

// DateTime wrapper for time.Time because the date format is "YYYY-MM-DD"
type DateTime struct {
	time.Time
}

func (c *DateTime) UnmarshalJSON(b []byte) error {
	value := strings.Trim(string(b), `"`) // get rid of bounding quotes `"`
	if value == "" || value == "null" {
		return nil
	}

	t, err := time.Parse("2006-01-02", value) // parse time format "YYYY-MM-DD"
	if err != nil {
		return err
	}
	*c = DateTime{t} // set result using the pointer to self
	return nil
}

func (c DateTime) MarshalJSON() ([]byte, error) {
	return []byte(`"` + c.Format("2006-01-02") + `"`), nil
}

// GetReleaseBranch returns the release branch for the given version. If not found,
// nil is returned.
func (r Releases) GetReleaseBranch(version string) *ReleaseBranch {
	for _, branch := range r.ReleaseBranches {
		if branch.ReleaseBranch == version {
			return &branch
		}
	}
	return nil
}

// KeysFor returns the keys for the given architecture and date. The date is used to check
// for deprecation.
func (r ReleaseBranch) KeysFor(arch string, date time.Time) []string {
	var urls []string
	keyset, ok := r.Keys[arch]
	if !ok {
		return urls
	}
	for _, key := range keyset {
		// check if expired
		if key.Deprecated.IsZero() || key.Deprecated.After(date) {
			// because of a bug in the urls as published; this should have been %40 (@) instead of %20 (space)
			key.URL = strings.ReplaceAll(key.URL, "%20", "@")
			urls = append(urls, key.URL)
		}
	}
	return urls
}
