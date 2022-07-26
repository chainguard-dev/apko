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

package apk_test

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/apk"
	"chainguard.dev/apko/pkg/apk/apkfakes"
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
		{ // InitRepositories fails
			prepare: func(fai *apkfakes.FakeApkImplementation) {
				fai.InitRepositoriesReturns(fakeErr)
			},
			msg:         "InitRepositories should fail",
			shouldError: true,
		},
		{ // InitWorld fails
			prepare: func(fai *apkfakes.FakeApkImplementation) {
				fai.InitWorldReturns(fakeErr)
			},
			msg:         "InitWorld should fail",
			shouldError: true,
		},
		{ // FixateWorld fails
			prepare: func(fai *apkfakes.FakeApkImplementation) {
				fai.FixateWorldReturns(fakeErr)
			},
			msg:         "FixateWorld should fail",
			shouldError: true,
		},
		{ // NormalizeScriptsTar fails
			prepare: func(fai *apkfakes.FakeApkImplementation) {
				fai.NormalizeScriptsTarReturns(fakeErr)
			},
			msg:         "NormalizeScriptsTar should fail",
			shouldError: true,
		},
	} {
		mock := &apkfakes.FakeApkImplementation{}
		tc.prepare(mock)

		sut := apk.New()
		sut.SetImplementation(mock)
		err := sut.Initialize(&types.ImageConfiguration{})
		if tc.shouldError {
			require.Error(t, err, tc.msg)
		} else {
			require.NoError(t, err, tc.msg, err)
		}
	}
}

func TestAddPackageVersionTag(t *testing.T) {
	td := t.TempDir()
	contents := `
D: hi
P:go
V:1.18
A:hello

P:nginx
A:priya
`
	if err := os.MkdirAll(filepath.Join(td, "lib/apk/db/"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(filepath.Join(td, "lib/apk/db/installed"), []byte(contents), 0755); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		description       string
		packageVersionTag string
		tags              []string
		expectedTags      []string
	}{
		{
			description:       "tag with go",
			packageVersionTag: "go",
			tags:              []string{"gcr.io/myimage/go:latest"},
			expectedTags:      []string{"gcr.io/myimage/go:latest", "gcr.io/myimage/go:1.18"},
		}, {
			description:       "nginx has no version",
			packageVersionTag: "nginx",
			tags:              []string{"gcr.io/myimage/go:latest"},
			expectedTags:      []string{"gcr.io/myimage/go:latest"},
		},
	}
	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			a := &apk.APK{Options: &options.Options{
				PackageVersionTag: test.packageVersionTag,
				Tags:              test.tags,
				WorkDir:           td,
				Log:               &logrus.Logger{},
			}}
			if err := a.AddPackageVersionTag(a.Options); err != nil {
				t.Fatal(err)
			}
			got := a.Options.Tags
			if d := cmp.Diff(got, test.expectedTags); d != "" {
				t.Fatalf("actual does not match expected: %s", d)
			}
		})
	}
}
