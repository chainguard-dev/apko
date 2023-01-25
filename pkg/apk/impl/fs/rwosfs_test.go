// Copyright 2022, 2023 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEmptyDir(t *testing.T) {
	dir := t.TempDir()
	fs := DirFS(dir)
	require.NotNil(t, fs, "fs should be created")
}

func TestExistingDir(t *testing.T) {
	var (
		err     error
		content []byte
	)
	files := []struct {
		path    string
		dir     bool
		perms   os.FileMode
		content []byte
	}{
		{"a/b", true, 0o755, nil},
		{"a/b/c", false, 0o644, []byte("hello")},
		{"foo/bar", true, 0o700, nil},
		{"foo/bar/world", false, 0o600, []byte("world")},
	}

	dir := t.TempDir()
	for _, f := range files {
		if f.dir {
			err = os.MkdirAll(filepath.Join(dir, f.path), f.perms)
			require.NoError(t, err, "error creating dir %s", f.path)
		} else {
			err = os.WriteFile(filepath.Join(dir, f.path), f.content, f.perms)
			require.NoError(t, err, "error creating file %s", f.path)
		}
	}

	fs := DirFS(dir)
	require.NotNil(t, fs, "fs should be created")

	for _, f := range files {
		if f.dir {
			continue
		}
		content, err = fs.ReadFile(f.path)
		require.NoError(t, err, "error reading file %s", f.path)
		require.Equal(t, f.content, content, "content of %s should be %s", f.path, f.content)
	}
}

func TestMissingDir(t *testing.T) {
	dir := t.TempDir()
	fs := DirFS(dir)
	require.NotNil(t, fs, "fs should be created")
	err := fs.WriteFile("foo/bar/world", []byte("world"), 0o600)
	require.Error(t, err, "expected error writing file foo/bar/world when foo/bar dir does not exist")
}
