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

package build

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSystemKeyringLocations(t *testing.T) {
	dir := t.TempDir()

	c := Context{
		Options: Options{
			Log: log.Default(),
		},
	}
	// Read the empty dir, passing only one empty location should err
	_, err := c.loadSystemKeyring(dir)
	require.Error(t, err)

	// Write some dummy keyfiles
	for _, h := range []string{"4a6a0840", "5243ef4b", "5261cecb", "6165ee59", "61666e3f"} {
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, fmt.Sprintf("alpine-devel@lists.alpinelinux.org-%s.rsa.pub", h)),
			[]byte("testABC"), os.FileMode(0o644),
		))
	}

	// Add a redme file to ensure we dont read it
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "README.txt"), []byte("testABC"), os.FileMode(0o644),
	))

	// Successful read
	keyFiles, err := c.loadSystemKeyring(dir)
	require.NoError(t, err)
	require.Len(t, keyFiles, 5)
	// should not take into account extraneous files
	require.NotContains(t, keyFiles, filepath.Join(dir, "README.txt"))

	// Unreadable directory should return error
	require.NoError(t, os.Chmod(dir, 0o000))
	_, err = c.loadSystemKeyring(dir)
	require.Error(t, err)

	// reset permissions back to 0700 or the tmpdir won't be removed
	require.NoError(t, os.Chmod(dir, 0o700))
}
