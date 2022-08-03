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

package vcs

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
)

// Given a starting directory and toplevel directory, work backwards
// to the toplevel directory and probe for a Git repository, returning
// the origin URI if known.
func ProbeDirForVCSUrl(startDir, toplevelDir string) (string, error) {
	for l, d := range map[string]string{
		"start": startDir, "top-level": toplevelDir,
	} {
		fi, err := os.Stat(d)
		if err != nil {
			return "", fmt.Errorf("cannot check %s directory: %w", l, err)
		}

		if !fi.IsDir() {
			return "", fmt.Errorf("%s path %s is not a directory", l, d)
		}
	}

	searchPath := startDir

	for {
		if !strings.HasPrefix(searchPath, toplevelDir) {
			return "", fmt.Errorf("path %s is not contained by %s", searchPath, toplevelDir)
		}

		repo, err := git.PlainOpen(searchPath)
		if err != nil {
			searchPath = filepath.Dir(searchPath)
			continue
		}

		remote, err := repo.Remote("origin")
		if err != nil {
			return "", fmt.Errorf("unable to determine upstream git vcs url: %w", err)
		}

		remoteConfig := remote.Config()
		remoteURL := remoteConfig.URLs[0]

		normalizedURL, err := url.Parse(remoteURL)
		if err != nil {
			// URL is most likely a git+ssh:// type URL, represented
			// in the way git itself does so.

			// Take the user@host:repo and turn it into user@host/repo.
			remoteURL = strings.Replace(remoteURL, ":", "/", 1)
			remoteURL = fmt.Sprintf("git+ssh://%s", remoteURL)

			normalizedURL, err = url.Parse(remoteURL)
			if err != nil {
				return "", fmt.Errorf("unable to parse %s as a git vcs url: %w", remoteURL, err)
			}
		}

		// sanitize any user authentication data from the VCS URL
		normalizedURL.User = nil

		return normalizedURL.String(), nil
	}
}

// Given a starting directory, work backwards to the current working
// directory and probe for a Git repository, returning the origin URI
// if known.
func ProbeDirFromPath(startingPath string) (string, error) {
	toplevelDir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("cannot find working directory: %w", err)
	}

	startingPath, err = filepath.Abs(startingPath)
	if err != nil {
		return "", fmt.Errorf("cannot dereference relative path %s: %w", startingPath, err)
	}

	fi, err := os.Stat(startingPath)
	if err != nil {
		return "", fmt.Errorf("cannot check start directory: %w", err)
	}

	// If starting path is not a directory, get the parent directory.
	// This way we can just pass things like "foo/apko.yaml" as the
	// input here.
	if !fi.IsDir() {
		startingPath = filepath.Dir(startingPath)
	}

	return ProbeDirForVCSUrl(startingPath, toplevelDir)
}
