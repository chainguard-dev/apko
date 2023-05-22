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

package tarball_test

import (
	"bytes"
	"embed"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/tarball"
)

//go:embed testdata
var testdataFS embed.FS

//go:embed testdata/foo
var fooFS embed.FS

//go:embed testdata/bar
var barFS embed.FS

func TestMultiTar(t *testing.T) {
	ctx, err := tarball.NewContext()
	require.NoError(t, err)

	var got bytes.Buffer

	m := tarball.Out(&got)
	require.NoError(t, m.Append(ctx, testdataFS))
	m.Close()

	var expected bytes.Buffer
	_, err = ctx.WriteArchive(&expected, testdataFS)
	require.NoError(t, err)

	require.Equal(t, expected, got)
}

func TestExtraWriter(t *testing.T) {
	ctx, err := tarball.NewContext()
	require.NoError(t, err)

	var gotFoo bytes.Buffer
	var gotBar bytes.Buffer

	m := tarball.Out(io.Discard)
	require.NoError(t, m.Append(ctx, barFS, &gotBar))
	require.NoError(t, m.Append(ctx, fooFS, &gotFoo))
	m.Close()

	var expectedFoo bytes.Buffer
	var expectedBar bytes.Buffer
	_, err = ctx.WriteArchive(&expectedBar, barFS)
	require.NoError(t, err)
	_, err = ctx.WriteArchive(&expectedFoo, fooFS)
	require.NoError(t, err)

	require.Equal(t, expectedFoo, gotFoo)
	require.Equal(t, expectedBar, gotBar)
}
