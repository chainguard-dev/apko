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

package sbom_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gitlab.alpinelinux.org/alpine/go/pkg/repository"

	"chainguard.dev/apko/pkg/sbom"
	"chainguard.dev/apko/pkg/sbom/sbomfakes"
)

var errFake = fmt.Errorf("synthetic error")

func TestGenerate(t *testing.T) {
	for _, tc := range []struct {
		prepare func(*sbomfakes.FakeSbomImplementation)
		assert  func([]string, error)
	}{
		{
			// CheckGenerators errors
			prepare: func(fsi *sbomfakes.FakeSbomImplementation) {
				fsi.CheckGeneratorsReturns(errFake)
			},
			assert: func(s []string, err error) {
				require.Error(t, err)
			},
		},
		{
			// Generate fails
			prepare: func(fsi *sbomfakes.FakeSbomImplementation) {
				fsi.CheckGeneratorsReturns(nil)
				fsi.GenerateReturns(nil, errFake)
			},
			assert: func(s []string, err error) {
				require.Error(t, err)
			},
		},
		{
			// Success
			prepare: func(fsi *sbomfakes.FakeSbomImplementation) {
				fsi.GenerateReturns([]string{"/path/to/sbom.cdx"}, nil)
			},
			assert: func(s []string, err error) {
				require.GreaterOrEqual(t, len(s), 1)
				require.NoError(t, err)
			},
		},
	} {
		mock := &sbomfakes.FakeSbomImplementation{}
		tc.prepare(mock)

		sut := sbom.SBOM{}
		sut.SetImplementation(mock)

		obj, err := sut.Generate()
		tc.assert(obj, err)
	}
}

func TestReadPackageIndes(t *testing.T) {
	for _, tc := range []struct {
		prepare func(*sbomfakes.FakeSbomImplementation)
		assert  func([]*repository.Package, error)
	}{
		{
			// ReadPackageIndex fails
			prepare: func(fsi *sbomfakes.FakeSbomImplementation) {
				fsi.ReadPackageIndexReturns(nil, errFake)
			},
			assert: func(pkgs []*repository.Package, err error) {
				require.Error(t, err)
			},
		},
		{
			// Success
			prepare: func(fsi *sbomfakes.FakeSbomImplementation) {
				fsi.ReadPackageIndexReturns([]*repository.Package{{}}, nil)
			},
			assert: func(pkgs []*repository.Package, err error) {
				require.GreaterOrEqual(t, len(pkgs), 1)
				require.NoError(t, err)
			},
		},
	} {
		mock := &sbomfakes.FakeSbomImplementation{}
		tc.prepare(mock)

		sut := sbom.SBOM{}
		sut.SetImplementation(mock)

		err := sut.ReadPackageIndex()
		tc.assert(sut.Options.Packages, err)
	}
}

func TestReadReleaseData(t *testing.T) {
	for _, tc := range []struct {
		prepare func(*sbomfakes.FakeSbomImplementation)
		assert  func(error)
	}{
		{
			// ReadReleaseData fails
			prepare: func(fsi *sbomfakes.FakeSbomImplementation) {
				fsi.ReadReleaseDataReturns(errFake)
			},
			assert: func(err error) {
				require.Error(t, err)
			},
		},
		{
			// Success
			prepare: func(fsi *sbomfakes.FakeSbomImplementation) {
				fsi.ReadReleaseDataReturns(nil)
			},
			assert: func(err error) {
				require.NoError(t, err)
			},
		},
	} {
		mock := &sbomfakes.FakeSbomImplementation{}
		tc.prepare(mock)

		sut := sbom.SBOM{}
		sut.SetImplementation(mock)

		err := sut.ReadReleaseData()
		tc.assert(err)
	}
}
