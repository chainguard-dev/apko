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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	apkfs "chainguard.dev/apko/pkg/apk/impl/fs"
)

func TestGetWorld(t *testing.T) {
	src := apkfs.NewMemFS()
	err := src.MkdirAll("etc/apk", 0755)
	require.NoError(t, err, "unable to mkdir /etc/apk")
	packages := []string{"package1", "package2", "package3"}
	err = src.WriteFile(worldFilePath, []byte(strings.Join(packages, "\n")), 0644)
	require.NoError(t, err, "unable to write world file")
	a, err := NewAPKImplementation(WithFS(src), WithIgnoreMknodErrors(ignoreMknodErrors))
	require.NoError(t, err, "unable to create APKImplementation")
	pkgs, err := a.GetWorld()
	require.NoError(t, err, "unable to get world packages")
	require.Equal(t, strings.Join(packages, " "), strings.Join(pkgs, " "), "expected packages %v, got %v", packages, pkgs)
}
