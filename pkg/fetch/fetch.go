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

package fetch

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
)

func Fetch(path string) ([]byte, error) {
	tempDir, err := os.MkdirTemp(os.TempDir(), "apko-fetch-*")
	if err != nil {
		return []byte{}, fmt.Errorf("failed to create tempdir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	pathElements := strings.Split(path, string(os.PathSeparator))

	// TODO(kaniini): We presently assume a github-like forge for figuring out
	// our paths.  Should come up with a better strategy at some point...
	uri := url.URL{
		Scheme: "https",
		Host:   pathElements[0],
		Path:   filepath.Join(pathElements[1:3]...),
	}

	repo, err := git.PlainClone(tempDir, false, &git.CloneOptions{
		URL: uri.String(),
	})
	if err != nil {
		return []byte{}, fmt.Errorf("failed to clone %s: %w", uri.String(), err)
	}

	ref, err := repo.Head()
	if err != nil {
		return []byte{}, fmt.Errorf("failed to fetch repository head: %w", err)
	}

	tree, err := repo.Worktree()
	if err != nil {
		return []byte{}, fmt.Errorf("failed to get worktree: %w", err)
	}

	err = tree.Checkout(&git.CheckoutOptions{
		Hash: ref.Hash(),
	})
	if err != nil {
		return []byte{}, fmt.Errorf("failed to checkout %s: %w", ref.Hash(), err)
	}

	paths := append([]string{tempDir}, pathElements[3:]...)
	target := filepath.Join(paths...)

	data, err := os.ReadFile(target)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to load fetched remote include %s: %w", target, err)
	}

	return data, nil
}
