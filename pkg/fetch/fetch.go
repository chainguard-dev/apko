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
	"github.com/go-git/go-git/v5/plumbing"
)

type Resource struct {
	Host       string
	Repository string
	Path       string
	Reference  string
}

func (r *Resource) URI() *url.URL {
	return &url.URL{
		Scheme: "https",
		Host:   r.Host,
		Path:   r.Repository,
	}
}

func (r *Resource) String() string {
	baseRef := strings.Join([]string{r.Host, r.Repository, r.Path}, "/")

	if r.Reference != "" {
		return fmt.Sprintf("%s@%s", baseRef, r.Reference)
	}

	return baseRef
}

func ParseRef(path string) (*Resource, error) {
	paths, referenceName, _ := strings.Cut(path, "@")
	pathElements := strings.Split(paths, string(os.PathSeparator))

	// TODO(kaniini): We presently assume a github-like forge for figuring out
	// our paths.  Should come up with a better strategy at some point...
	ref := Resource{
		Host:       pathElements[0],
		Repository: filepath.Join(pathElements[1:3]...),
		Path:       filepath.Join(pathElements[3:]...),
		Reference:  referenceName,
	}

	return &ref, nil
}

func Fetch(path string) ([]byte, error) {
	tempDir, err := os.MkdirTemp(os.TempDir(), "apko-fetch-*")
	if err != nil {
		return []byte{}, fmt.Errorf("failed to create tempdir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	resource, err := ParseRef(path)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to parse git reference %s: %w", path, err)
	}

	repo, err := git.PlainClone(tempDir, false, &git.CloneOptions{
		URL: resource.URI().String(),
	})
	if err != nil {
		return []byte{}, fmt.Errorf("failed to clone %s: %w", resource.String(), err)
	}

	var hash *plumbing.Hash

	if resource.Reference == "" {
		ref, err := repo.Head()
		if err != nil {
			return []byte{}, fmt.Errorf("failed to fetch repository head: %w", err)
		}

		refHash := ref.Hash()
		hash = &refHash
	} else {
		rev := plumbing.Revision(resource.Reference)

		hash, err = repo.ResolveRevision(rev)
		if err != nil {
			return []byte{}, fmt.Errorf("failed to fetch repository rev %s: %w", resource.Reference, err)
		}
	}

	tree, err := repo.Worktree()
	if err != nil {
		return []byte{}, fmt.Errorf("failed to get worktree: %w", err)
	}

	err = tree.Checkout(&git.CheckoutOptions{
		Hash: *hash,
	})
	if err != nil {
		return []byte{}, fmt.Errorf("failed to checkout %s: %w", *hash, err)
	}

	paths := append([]string{tempDir}, resource.Path)
	target := filepath.Join(paths...)

	data, err := os.ReadFile(target)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to load fetched remote include %s: %w", target, err)
	}

	return data, nil
}
