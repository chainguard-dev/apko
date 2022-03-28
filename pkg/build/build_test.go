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

package build_test

import (
	"fmt"
	"testing"

	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/build/buildfakes"
	"github.com/stretchr/testify/require"
)

func TestBuildLayer(t *testing.T) {
	fakeErr := fmt.Errorf("synthetic error")
	for _, tc := range []struct {
		prepare     func(*buildfakes.FakeBuildImplementation)
		shouldError bool
	}{
		{ // success
			prepare: func(fbi *buildfakes.FakeBuildImplementation) {
				// noop.
			},
			shouldError: false,
		},
		{ // Build Image fails
			prepare: func(fbi *buildfakes.FakeBuildImplementation) {
				fbi.BuildImageReturns(fakeErr)
			},
			shouldError: true,
		},
		{ // BuildTarball fails
			prepare: func(fbi *buildfakes.FakeBuildImplementation) {
				fbi.BuildTarballReturns("", fakeErr)
			},
			shouldError: true,
		},
		{
			// GenerateSBOM fails
			prepare: func(fbi *buildfakes.FakeBuildImplementation) {
				fbi.GenerateSBOMReturns(fakeErr)
			},
			shouldError: true,
		},
	} {
		mock := buildfakes.FakeBuildImplementation{}
		tc.prepare(&mock)
		sut, err := build.New("/mock")
		require.NoError(t, err)
		sut.SetImplementation(&mock)
		_, err = sut.BuildLayer()
		if tc.shouldError {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
	}
}
