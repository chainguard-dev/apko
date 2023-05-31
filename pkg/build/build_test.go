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
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/build/buildfakes"
)

func TestBuildLayer(t *testing.T) {
	fakeErr := fmt.Errorf("synthetic error")
	for _, tc := range []struct {
		prepare     func(*buildfakes.FakeBuildImplementation)
		msg         string
		shouldError bool
	}{
		{ // success
			prepare: func(fbi *buildfakes.FakeBuildImplementation) {
				fbi.BuildTarballReturns("", sha256.New(), sha256.New(), 0, nil)
			},
			msg:         "success",
			shouldError: false,
		},
		{ // Build Image fails
			prepare: func(fbi *buildfakes.FakeBuildImplementation) {
				fbi.ValidateImageConfigurationReturns(fakeErr)
			},
			msg:         "BuildImage should fail",
			shouldError: true,
		},
		{ // BuildTarball fails
			prepare: func(fbi *buildfakes.FakeBuildImplementation) {
				fbi.BuildTarballReturns("", sha256.New(), sha256.New(), 0, fakeErr)
			},
			msg:         "buildtarball fails",
			shouldError: true,
		},
		{
			// GenerateSBOM fails
			prepare: func(fbi *buildfakes.FakeBuildImplementation) {
				fbi.GenerateSBOMReturns(fakeErr)
			},
			msg:         "generate sbom should fail",
			shouldError: true,
		},
	} {
		t.Run(tc.msg, func(t *testing.T) {
			mock := buildfakes.FakeBuildImplementation{}
			tc.prepare(&mock)
			sut, err := build.New(t.TempDir())
			sut.Options.WantSBOM = true
			require.NoError(t, err)
			sut.SetImplementation(&mock)
			_, _, err = sut.BuildLayer()
			if tc.shouldError {
				require.Error(t, err, tc.msg)
			} else {
				require.NoError(t, err, tc.msg)
			}
		})
	}
}

func TestBuildImage(t *testing.T) {
	fakeErr := fmt.Errorf("synthetic error")
	for _, tc := range []struct {
		prepare     func(*buildfakes.FakeBuildImplementation)
		msg         string
		shouldError bool
	}{
		{ // success
			prepare: func(fbi *buildfakes.FakeBuildImplementation) {

			},
			msg:         "build image succeeds",
			shouldError: false,
		},
		{
			// ValidateImageConfiguration fails
			prepare: func(fbi *buildfakes.FakeBuildImplementation) {
				fbi.ValidateImageConfigurationReturns(fakeErr)
			},
			msg:         "ValidateImageConfiguration fails",
			shouldError: true,
		},
		{
			// InitializeApk fails
			prepare: func(fbi *buildfakes.FakeBuildImplementation) {
				fbi.InitializeApkReturns(fakeErr)
			},
			msg:         "InitializeApk fails",
			shouldError: true,
		},
		{
			// MutateAccounts fails
			prepare: func(fbi *buildfakes.FakeBuildImplementation) {
				fbi.MutateAccountsReturns(fakeErr)
			},
			msg:         "MutateAccounts fails",
			shouldError: true,
		},
		{
			// WriteSupervisionTree fails
			prepare: func(fbi *buildfakes.FakeBuildImplementation) {
				fbi.WriteSupervisionTreeReturns(fakeErr)
			},
			msg:         "WriteSupervisionTree fails",
			shouldError: true,
		},
	} {
		mock := &buildfakes.FakeBuildImplementation{}
		tc.prepare(mock)
		sut, err := build.New(t.TempDir())
		require.NoError(t, err)
		sut.SetImplementation(mock)
		_, err = sut.BuildImage()
		if tc.shouldError {
			require.Error(t, err, tc.msg)
		} else {
			require.NoError(t, err, tc.msg, err)
		}
	}
}
