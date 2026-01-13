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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/charmbracelet/log"
)

// for fetching the alpine keys
const alpineReleasesURL = "https://alpinelinux.org/releases.json"

type NoKeysFoundError struct {
	archs    []string
	releases []string
}

func (e *NoKeysFoundError) Error() string {
	return fmt.Sprintf("no keys found for arch %v and releases %v", e.archs, e.releases)
}

func fetchAlpineKeyURLs(ctx context.Context, fetcher Fetcher, archs []string, alpineVersions []string) ([]string, error) {
	u := alpineReleasesURL

	// NB: Not setting basic auth, since we know Alpine doesn't support it.
	res, err := fetcher(ctx, u, false)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch alpine releases: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unable to get alpine releases at %s: %v", u, res.Status)
	}

	b, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read alpine releases: %w", err)
	}

	var releases Releases
	if err := json.Unmarshal(b, &releases); err != nil {
		return nil, fmt.Errorf("failed to unmarshal alpine releases: %w", err)
	}

	var urls []string
	// now just need to get the keys for the desired architecture and releases
	for _, version := range alpineVersions {
		branch := releases.GetReleaseBranch(version)
		if branch == nil {
			log.Debugf("Alpine version %s not found in releases", version)
			continue
		}

		for _, arch := range archs {
			archKeyURLs := branch.KeysFor(arch, time.Now())
			if len(archKeyURLs) == 0 {
				log.Debugf("No keys found for arch %s and version %s", arch, version)
				continue
			}

			urls = append(urls, archKeyURLs...)
		}
	}
	if len(urls) == 0 {
		return nil, &NoKeysFoundError{archs: archs, releases: alpineVersions}
	}

	return urls, nil
}
