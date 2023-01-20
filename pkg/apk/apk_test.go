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

package apk

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/apk/apkfakes"
	apkfs "chainguard.dev/apko/pkg/apk/impl/fs"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/options"
)

func TestInitialize(t *testing.T) {
	fakeErr := fmt.Errorf("synthetic error")
	for _, tc := range []struct {
		prepare     func(*apkfakes.FakeApkImplementation)
		msg         string
		shouldError bool
	}{
		{ // success
			prepare: func(fai *apkfakes.FakeApkImplementation) {

			},
			msg:         "init succeeds",
			shouldError: false,
		},
		{ // InitKeyring fails
			prepare: func(fai *apkfakes.FakeApkImplementation) {
				fai.InitKeyringReturns(fakeErr)
			},
			msg:         "InitKeyring should fail",
			shouldError: true,
		},
		{ // SetRepositories fails
			prepare: func(fai *apkfakes.FakeApkImplementation) {
				fai.SetRepositoriesReturns(fakeErr)
			},
			msg:         "SetRepositories should fail",
			shouldError: true,
		},
		{ // SetWorld fails
			prepare: func(fai *apkfakes.FakeApkImplementation) {
				fai.SetWorldReturns(fakeErr)
			},
			msg:         "SetWorld should fail",
			shouldError: true,
		},
		{ // FixateWorld fails
			prepare: func(fai *apkfakes.FakeApkImplementation) {
				fai.FixateWorldReturns(fakeErr)
			},
			msg:         "FixateWorld should fail",
			shouldError: true,
		},
	} {
		mock := &apkfakes.FakeApkImplementation{}
		tc.prepare(mock)
		workDir := t.TempDir()
		fsys := apkfs.DirFS(workDir)
		sut, err := NewWithOptions(fsys, options.Options{
			WorkDir: workDir,
		})
		require.NoError(t, err)
		sut.SetImplementation(mock)
		err = sut.Initialize(&types.ImageConfiguration{})
		if tc.shouldError {
			require.Error(t, err, tc.msg)
		} else {
			require.NoError(t, err, tc.msg, err)
		}
	}
}

func TestAdditionalTags(t *testing.T) {
	td := t.TempDir()
	contents := `
D: hi
P:go
V:1.18
A:hello

P:nginx
A:priya

P:boop
V:10.45.6-r5
A:bop

`
	if err := os.MkdirAll(filepath.Join(td, "lib/apk/db/"), 0755); err != nil {
		require.Error(t, err, "mkdir all dirs failed")
	}
	if err := os.WriteFile(filepath.Join(td, "lib/apk/db/installed"), []byte(contents), 0755); err != nil {
		require.Error(t, err, "write file failed")
	}
	tests := []struct {
		description             string
		packageVersionTag       string
		packageVersionTagStem   bool
		packageVersionTagPrefix string
		tags                    []string
		expectedTags            []string
	}{
		{
			description:       "tag with go",
			packageVersionTag: "go",
			tags:              []string{"gcr.io/myimage/go:latest"},
			expectedTags:      []string{"gcr.io/myimage/go:1.18"},
		}, {
			description:       "nginx has no version",
			packageVersionTag: "nginx",
			tags:              []string{"gcr.io/myimage/nginx:latest"},
			expectedTags:      nil,
		},
		{
			description:           "tag with boop",
			packageVersionTag:     "boop",
			packageVersionTagStem: false,
			tags:                  []string{"gcr.io/myimage/boop:latest"},
			expectedTags:          []string{"gcr.io/myimage/boop:10.45.6-r5"},
		},
		{
			description:           "tag with boop (stemmed)",
			packageVersionTag:     "boop",
			packageVersionTagStem: true,
			tags:                  []string{"gcr.io/myimage/boop:latest"},
			expectedTags: []string{
				"gcr.io/myimage/boop:10.45.6-r5",
				"gcr.io/myimage/boop:10.45.6",
				"gcr.io/myimage/boop:10.45",
				"gcr.io/myimage/boop:10",
			},
		},
		{
			description:             "tag with boop (stemmed and prefixed)",
			packageVersionTag:       "boop",
			packageVersionTagStem:   true,
			packageVersionTagPrefix: "bam-",
			tags:                    []string{"gcr.io/myimage/boop:latest"},
			expectedTags: []string{
				"gcr.io/myimage/boop:bam-10.45.6-r5",
				"gcr.io/myimage/boop:bam-10.45.6",
				"gcr.io/myimage/boop:bam-10.45",
				"gcr.io/myimage/boop:bam-10",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.description, func(tt *testing.T) {
			opts := options.Options{
				PackageVersionTag:       test.packageVersionTag,
				PackageVersionTagStem:   test.packageVersionTagStem,
				PackageVersionTagPrefix: test.packageVersionTagPrefix,
				Tags:                    test.tags,
				WorkDir:                 td,
				Log:                     &logrus.Logger{},
			}
			fsys := apkfs.DirFS(td)
			got, err := AdditionalTags(fsys, opts)
			if err != nil {
				require.NoError(tt, fmt.Errorf("additional tags failed: %w", err))
			}
			if d := cmp.Diff(got, test.expectedTags); d != "" {
				require.NoError(tt, fmt.Errorf("does not match: %s", d), "actual does not match expected")
			}
		})
	}
}
