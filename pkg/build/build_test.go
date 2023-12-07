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

package build_test

import (
	"chainguard.dev/apko/pkg/build"
	"context"
	"github.com/chainguard-dev/go-apk/pkg/fs"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"testing"
)

func TestBuildLayer(t *testing.T) {
}

func TestBuildImage(t *testing.T) {
	ctx := context.Background()

	opts := []build.Option{
		build.WithConfig(filepath.Join("testdata", "tzdata.yaml")),
	}

	bc, err := build.New(ctx, fs.NewMemFS(), opts...)
	if err != nil {
		t.Fatal(err)
	}

	if err := bc.BuildImage(ctx); err != nil {
		t.Fatal(err)
	}

	installed, err := bc.InstalledPackages()
	if err != nil {
		t.Fatal(err)
	}

	require.Len(t, installed, 1)
	require.Equal(t, installed[0].Name, "tzdata")
	require.Equal(t, installed[0].Version, "2023c-r0")
}

func TestBuildImageFromResolvedFile(t *testing.T) {
	ctx := context.Background()

	opts := []build.Option{
		build.WithConfig(filepath.Join("testdata", "tzdata.yaml")),
		build.WithResolvedFile(filepath.Join("testdata", "tzdata.resolved.json")),
	}

	bc, err := build.New(ctx, fs.NewMemFS(), opts...)
	if err != nil {
		t.Fatal(err)
	}

	if err := bc.BuildImage(ctx); err != nil {
		t.Fatal(err)
	}

	installed, err := bc.InstalledPackages()
	if err != nil {
		t.Fatal(err)
	}

	require.Len(t, installed, 1)
	require.Equal(t, installed[0].Name, "tzdata")
	require.Equal(t, installed[0].Version, "2023c-r0")
}

func TestBuildImageFromTooOldResolvedFile(t *testing.T) {
	ctx := context.Background()

	opts := []build.Option{
		build.WithConfig(filepath.Join("testdata", "tzdata.yaml")),
		build.WithResolvedFile(filepath.Join("testdata", "tzdata.pre-0.11.resolved.json")),
	}

	bc, err := build.New(ctx, fs.NewMemFS(), opts...)
	if err != nil {
		t.Fatal(err)
	}
	err = bc.BuildImage(ctx)
	require.Equal(t, "failed installation from resolved-file testdata/tzdata.pre-0.11.resolved.json: "+
		"locked package tzdata has missing checksum (please regenerate the lock file (resolved-file) with Apko >=0.12)",
		err.Error())
}
