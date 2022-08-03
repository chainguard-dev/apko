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
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/release-utils/tar"
)

func createTestRepo(t *testing.T) string {
	// This is a tarball of an empty repo with a single
	// Initial Commit (421a8437f04bc1693a8e45e9cb940278cabef756)
	// Second Commit (9f7ff0afdae5d8b1cf7761369ee42b3343ba750b)
	repoContents := `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
AAAAAAAAAAAAAAAAAAAAAABgAP8BiBaLcAB4AAA=`

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
			topDir:    "/tmp",
			prepare: func() (string, error) {
				dir := createTestRepo(t)
				require.NoError(t, os.MkdirAll(filepath.Join(os.TempDir(), "a", "b"), os.FileMode(0o755)))
				return dir, nil
			},
		},
		{
			// No repo until top
			shouldErr: true,
			topDir:    "/tmp",
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
