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

package sbom

import (
	"fmt"
	"os"
	"testing"

	apkfs "chainguard.dev/apko/pkg/apk/impl/fs"
	"chainguard.dev/apko/pkg/sbom/generator"
	"chainguard.dev/apko/pkg/sbom/generator/generatorfakes"

	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/sbom/options"
)

var errFake = fmt.Errorf("synthetic error")

func TestReadReleaseData(t *testing.T) {
	osinfoData := `ID=wolfi
NAME="Wolfi"
PRETTY_NAME="Wolfi"
VERSION_ID="2022, 20230914"
HOME_URL="https://wolfi.dev"
`
	fsys := apkfs.NewMemFS()
	require.NoError(
		t, fsys.WriteFile(
			"os-release", []byte(osinfoData), os.FileMode(0o644),
		),
	)
	di := defaultSBOMImplementation{}

	// Non existent file, should err
	require.Error(t, di.ReadReleaseData(fsys, &options.Options{}, "non-existent"))
	opts := options.Options{}
	require.NoError(t, di.ReadReleaseData(fsys, &opts, "os-release"))
	require.Equal(t, "wolfi", opts.OS.ID, "id")
	require.Equal(t, "Wolfi", opts.OS.Name, "name")
	require.Equal(t, "2022, 20230914", opts.OS.Version, "version")
}

func TestReadReleaseData_EmptyDefaults(t *testing.T) {
	fsys := apkfs.NewMemFS()
	require.NoError(
		t, fsys.WriteFile(
			"os-release", nil, os.FileMode(0o644),
		),
	)
	di := defaultSBOMImplementation{}

	// Non existent file, should err
	require.Error(t, di.ReadReleaseData(fsys, &options.Options{}, "non-existent"))
	opts := options.Options{}
	require.NoError(t, di.ReadReleaseData(fsys, &opts, "os-release"))
	require.Equal(t, "", opts.OS.ID, "id")
	require.Equal(t, "", opts.OS.Name, "name")
	require.Equal(t, "", opts.OS.Version, "version")
}

func TestReadPackageIndex(t *testing.T) {
	sampleDB := `
C:Q1Deb0jNytkrjPW4N/eKLZ43BwOlw=
P:musl
V:1.2.2-r7
A:x86_64
S:383152
I:622592
T:the musl c library (libc) implementation
U:https://musl.libc.org/
L:MIT
o:musl
m:Pkg Author <user@domain.com>
t:1632431095
c:bf5bbfdbf780092f387b7abe401fbfceda90c84d
p:so:libc.musl-x86_64.so.1=1
F:lib
R:ld-musl-x86_64.so.1
a:0:0:755
Z:Q12adwqQOjo9dFl+VJD2Ecd901vhE=
R:libc.musl-x86_64.so.1
a:0:0:777
Z:Q17yJ3JFNypA4mxhJJr0ou6CzsJVI=

C:Q1UQjutTNeqKQgMlKQyyZFnumOg3c=
P:libretls
V:3.3.4-r2
A:x86_64
S:29183
I:86016
T:port of libtls from libressl to openssl
U:https://git.causal.agency/libretls/
L:ISC AND (BSD-3-Clause OR MIT)
o:libretls
m:Pkg Author <user@domain.com>
t:1634364270
c:670bf5a8cc5bc605eede8ca2fd55b50a5c9f8660
D:ca-certificates-bundle so:libc.musl-x86_64.so.1 so:libcrypto.so.1.1 so:libssl.so.1.1
p:so:libtls.so.2=2.0.3
F:usr
F:usr/lib
R:libtls.so.2
a:0:0:777
Z:Q1nNEC9T/t6W+Ecm0DxqMUnRvcT6k=
R:libtls.so.2.0.3
a:0:0:755
Z:Q1/KAM0XSmA+YShex9ZKehdaf+mjw=

`
	fsys := apkfs.NewMemFS()
	require.NoError(
		t, fsys.WriteFile(
			"installed", []byte(sampleDB), os.FileMode(0o644),
		),
	)

	// Write an invalid DB
	require.NoError(
		t, fsys.WriteFile(
			"installed-corrupt",
			[]byte("sldkjflskdjflsjdflkjsdlfkjsldfkj\nskdjfhksjdhfkjhsdkfjhksdjhf"),
			os.FileMode(0o644),
		),
	)

	di := defaultSBOMImplementation{}

	// Non existent file must fail
	opts := &options.Options{}
	_, err := di.ReadPackageIndex(fsys, opts, "non-existent")
	require.Error(t, err)
	_, err = di.ReadPackageIndex(fsys, opts, "installed-corrupt")
	require.Error(t, err)
	pkg, err := di.ReadPackageIndex(fsys, opts, "installed")
	require.NoError(t, err)
	require.NotNil(t, pkg)
	require.Len(t, pkg, 2)
}

func TestCheckGenerators(t *testing.T) {
	di := defaultSBOMImplementation{}
	gen := generatorfakes.FakeGenerator{}

	// No generators set
	require.Error(t, di.CheckGenerators(
		&options.Options{Formats: []string{"cyclonedx"}},
		map[string]generator.Generator{},
	))
	// No generators enabled in the options
	require.Error(t, di.CheckGenerators(
		&options.Options{Formats: []string{}},
		map[string]generator.Generator{"fake": &gen},
	))
	// No generator for specified format
	require.Error(t, di.CheckGenerators(
		&options.Options{Formats: []string{"cyclonedx"}},
		map[string]generator.Generator{"fake": &gen},
	))
	// Success
	require.NoError(t, di.CheckGenerators(
		&options.Options{Formats: []string{"fake"}},
		map[string]generator.Generator{"fake": &gen},
	))
}

func TestGenerate(t *testing.T) {
	di := defaultSBOMImplementation{}
	outputDir := "/path/to/sbom"
	formats := []string{"fake"}

	for _, tc := range []struct {
		prepare func(*generatorfakes.FakeGenerator)
		opts    options.Options
		assert  func([]string, error)
	}{
		{
			// Success
			prepare: func(fg *generatorfakes.FakeGenerator) {
				fg.GenerateReturns(nil)
			},
			opts: options.Options{OutputDir: outputDir, Formats: formats},
			assert: func(sboms []string, err error) {
				require.NoError(t, err)
				require.GreaterOrEqual(t, len(sboms), 1)
			},
		},
		{
			// Generate fails
			prepare: func(fg *generatorfakes.FakeGenerator) {
				fg.GenerateReturns(errFake)
			},
			opts: options.Options{OutputDir: outputDir, Formats: formats},
			assert: func(s []string, err error) {
				require.Error(t, err)
			},
		},
	} {
		mock := &generatorfakes.FakeGenerator{}
		tc.prepare(mock)
		res, err := di.Generate(
			&tc.opts, map[string]generator.Generator{"fake": mock},
		)
		tc.assert(res, err)
	}
}
