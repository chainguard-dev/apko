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

package types

import (
	"context"
	"crypto/sha256"
	"path/filepath"
	"testing"
	"github.com/stretchr/testify/require"
)

func TestIncludeMergePackages(t *testing.T) {
	var ic ImageConfiguration
	hasher := sha256.New()
	ctx := context.Background()
	err := ic.Load(ctx, filepath.Join("testdata/include", "apko.yaml"), hasher)
	if err != nil {
		t.Fatal(err)
	}

	require.Equal(t, ic.Contents.Packages, []string{"pretend-baselayout", "replayout"})
}

func TestIncludeCmdTopImagePriority(t *testing.T) {
	var ic ImageConfiguration
	hasher := sha256.New()
	ctx := context.Background()
	err := ic.Load(ctx, filepath.Join("testdata/include", "apko.yaml"), hasher)
	if err != nil {
		t.Fatal(err)
	}

	require.Equal(t, ic.Cmd, "ls")
}

func TestIncludeEntrypointTopImagePriority(t *testing.T) {
	var ic ImageConfiguration
	hasher := sha256.New()
	ctx := context.Background()
	err := ic.Load(ctx, filepath.Join("testdata/include", "apko.yaml"), hasher)
	if err != nil {
		t.Fatal(err)
	}

	require.Equal(t, ic.Entrypoint.Command, "/bin/bash -l")
}

func TestIncludeMergedInheritAccounts(t *testing.T) {
	var ic ImageConfiguration
	hasher := sha256.New()
	ctx := context.Background()
	err := ic.Load(ctx, filepath.Join("testdata/include", "apko.yaml"), hasher)
	if err != nil {
		t.Fatal(err)
	}

	require.Equal(t, ic.Accounts.RunAs, "apko")
	require.Equal(t, ic.Accounts.Users, []User{
		{UserName: "apko", UID: uint32(10001), GID: uint32(0)},
		{UserName: "nonroot", UID: uint32(10000), GID: uint32(0)},
	})
}

func TestIncludeMergedInheritGroups(t *testing.T) {
	var ic ImageConfiguration
	hasher := sha256.New()
	ctx := context.Background()
	err := ic.Load(ctx, filepath.Join("testdata/include", "apko.yaml"), hasher)
	if err != nil {
		t.Fatal(err)
	}

	require.Equal(t, ic.Accounts.Groups, []Group{
		{GroupName: "apko", GID: uint32(10001)},
		{GroupName: "nonroot", GID: uint32(10000)},
	})
}

func TestIncludeMergedEnvironment(t *testing.T) {
	var ic ImageConfiguration
	hasher := sha256.New()
	ctx := context.Background()
	err := ic.Load(ctx, filepath.Join("testdata/include", "apko.yaml"), hasher)
	if err != nil {
		t.Fatal(err)
	}

	// inherit and overwrited environments
	expected := make(map[string]string)
	expected["LANG"] = "en_US.utf8"
	expected["LC_ALL"] = "C.utf8"

	require.Equal(t, ic.Environment, expected)
}

func TestIncludeMergedPathMutations(t *testing.T) {
	var ic ImageConfiguration
	hasher := sha256.New()
	ctx := context.Background()
	err := ic.Load(ctx, filepath.Join("testdata/include", "apko.yaml"), hasher)
	if err != nil {
		t.Fatal(err)
	}

	expected := []PathMutation{
		{Path: "/home/apko", UID: uint32(10001), GID: uint32(10001), Permissions: uint32(420), Type: "directory"},
		{Path: "/work", UID: uint32(10001), GID: uint32(10001), Permissions: uint32(420), Type: "directory"},
		{Path: "/testdata", UID: uint32(10000), GID: uint32(10000), Permissions: uint32(448), Type: "directory"},
	}

	require.Equal(t, ic.Paths, expected)
}
