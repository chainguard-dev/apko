// Copyright 2026 Chainguard, Inc.
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

package options

import (
	"testing"

	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/build/types"
)

func TestLayerFileName(t *testing.T) {
	for _, tc := range []struct {
		name   string
		arch   types.Architecture
		format types.LayerFormat
		want   string
	}{
		{"tar with arch", types.ParseArchitecture("amd64"), types.LayerFormatTar, "apko-x86_64.tar.gz"},
		{"empty format defaults to tar", types.ParseArchitecture("amd64"), "", "apko-x86_64.tar.gz"},
		{"tar without arch", "", types.LayerFormatTar, "apko.tar.gz"},
		{"erofs with arch", types.ParseArchitecture("arm64"), types.LayerFormatErofs, "apko-aarch64.erofs"},
		{"erofs without arch", "", types.LayerFormatErofs, "apko.erofs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := Options{Arch: tc.arch}
			require.Equal(t, tc.want, o.LayerFileName(tc.format))
		})
	}
}

// The tar spelling must not drift from TarballFileName, which other callers
// still use directly.
func TestLayerFileName_MatchesTarballFileName(t *testing.T) {
	o := Options{Arch: types.ParseArchitecture("amd64")}
	require.Equal(t, o.TarballFileName(), o.LayerFileName(types.LayerFormatTar))
}
