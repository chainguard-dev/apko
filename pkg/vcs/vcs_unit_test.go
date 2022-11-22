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

package vcs

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/release-utils/tar"
)

func createTestRepo(t *testing.T) string {
	// This is a tarball of an empty repo with two commits:
	// Initial Commit (421a8437f04bc1693a8e45e9cb940278cabef756)
	// Second Commit (9f7ff0afdae5d8b1cf7761369ee42b3343ba750b)
	// and one remote:
	// origin	git@github.com:example/example.git (fetch)
	repoContents := `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`

	tarFile, err := os.CreateTemp("", "repo-*.tar.gz")
	require.NoError(t, err)
	defer os.Remove(tarFile.Name())

	tarData, err := base64.StdEncoding.DecodeString(repoContents)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(tarFile.Name(), tarData, os.FileMode(0o644)))

	/// Create the directory
	tmpdir, err := os.MkdirTemp("", "testrepo-")
	require.NoError(t, os.RemoveAll(tmpdir))
	require.NoError(t, err)

	require.NoError(t, tar.Extract(tarFile.Name(), tmpdir))

	return tmpdir
}

func TestOpenRepository(t *testing.T) {
	for _, tc := range []struct {
		shouldErr bool
		topDir    string
		prepare   func() (string, error)
	}{
		{
			// Directory not resolvable with Abs()
			shouldErr: true,
			prepare:   func() (string, error) { return "/tmp/../../&", nil },
		},
		{
			// Directory does not exist
			shouldErr: true,
			prepare:   func() (string, error) { return "/lskjdflkjsdlfkjlskdjf", nil },
		},
		{
			// Directory is not a directory
			shouldErr: true,
			prepare: func() (string, error) {
				f, err := os.CreateTemp("", "vcs-test-")
				if err != nil {
					return "", err
				}
				return f.Name(), nil
			},
		},
		{
			// Directory is not contained in topLevelDir
			shouldErr: true,
			topDir:    "/usr/",
			prepare: func() (string, error) {
				dir, err := os.MkdirTemp("", "vcs-test-")
				if err != nil {
					return "", err
				}
				return dir, nil
			},
		},
		{
			// Subdirectory should work
			shouldErr: false,
			topDir:    os.TempDir(),
			prepare: func() (string, error) {
				dir := createTestRepo(t)
				require.NoError(t, os.MkdirAll(filepath.Join(os.TempDir(), "a", "b"), os.FileMode(0o755)))
				return dir, nil
			},
		},
		{
			// No repo until top
			shouldErr: true,
			topDir:    os.TempDir(),
			prepare: func() (string, error) {
				p := filepath.Join(os.TempDir(), "a", "b")
				err := os.MkdirAll(p, os.FileMode(0o755))
				return p, err
			},
		},
	} {
		dir, err := tc.prepare()
		require.NoError(t, err)
		defer func() {
			if strings.HasPrefix(dir, os.TempDir()) {
				require.NoError(t, os.RemoveAll(dir))
			}
		}()
		repo, err := OpenRepository(dir, tc.topDir)
		if tc.shouldErr {
			require.Nil(t, repo, "when failing, repo must be nil")
			require.Error(t, err)
		} else {
			require.NotNil(t, repo)
			require.NoError(t, err)
		}
	}
}

func TestResolveGitRevision(t *testing.T) {
	repoDir := createTestRepo(t)
	defer os.RemoveAll(repoDir)

	repo, err := OpenRepository(repoDir, "")
	require.NoError(t, err)

	for _, tc := range []struct {
		ref       string
		expected  string
		shouldErr bool
	}{
		{"HEAD", "9f7ff0afdae5d8b1cf7761369ee42b3343ba750b", false},
		{"HEAD~1", "421a8437f04bc1693a8e45e9cb940278cabef756", false},
		{"HEAD~2", "", true},
		{"9f7ff0afdae5d8b1cf7761369ee42b3343ba750b", "9f7ff0afdae5d8b1cf7761369ee42b3343ba750b", false},
	} {
		hash, err := resolveGitRevision(repo, tc.ref)
		if tc.shouldErr {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
			require.Equal(t, tc.expected, hash)
		}
	}
}

func TestGetRemoteURL(t *testing.T) {
	repoDir := createTestRepo(t)
	defer os.RemoveAll(repoDir)

	repo, err := OpenRepository(repoDir, "")
	require.NoError(t, err)

	for _, tc := range []struct {
		remoteName string
		URL        string
		shouldErr  bool
	}{
		{
			// Regular remote
			remoteName: defaultRemoteName,
			URL:        "git+ssh://github.com/example/example.git",
			shouldErr:  false,
		},
		{
			// Empty name should default to same
			remoteName: "",
			URL:        "git+ssh://github.com/example/example.git",
			shouldErr:  false,
		},
		{
			// Non existing remote should fail
			remoteName: "upstream",
			shouldErr:  true,
		},
	} {
		url, err := getRemoteURL(repo, tc.remoteName)
		if tc.shouldErr {
			require.Error(t, err)
			require.Empty(t, url)
			continue
		}
		require.NoError(t, err)
		require.Equal(t, tc.URL, url)
	}
}
