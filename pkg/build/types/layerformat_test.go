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

package types

import "testing"

func TestLayerFormat(t *testing.T) {
	tests := []struct {
		spec       string
		wantBase   LayerFormat
		wantComp   string
		wantLevel  int
		wantHasLvl bool
		wantValid  bool
	}{
		// Default empty → tar.
		{"", LayerFormatTar, "", 0, false, true},
		{"tar", LayerFormatTar, "", 0, false, true},
		{"erofs", LayerFormatErofs, "", 0, false, true},
		{"erofs+zstd", LayerFormatErofs, "zstd", 0, false, true},
		{"erofs+zstd,level=3", LayerFormatErofs, "zstd", 3, true, true},
		{"erofs+zstd,level=22", LayerFormatErofs, "zstd", 22, true, true},
		{"erofs+lz4", LayerFormatErofs, "lz4", 0, false, true},
		{"erofs+lz4hc,level=9", LayerFormatErofs, "lz4hc", 9, true, true},
		{"erofs+deflate", LayerFormatErofs, "deflate", 0, false, true},

		// Rejected: compressor on tar.
		{"tar+gzip", LayerFormatTar, "gzip", 0, false, false},
		// Rejected: unknown compressor.
		{"erofs+xyz", LayerFormatErofs, "xyz", 0, false, false},
		// Rejected: unknown base.
		{"squashfs", "squashfs", "", 0, false, false},
		// Rejected: level= value doesn't parse as an integer.
		{"erofs+zstd,level=oops", LayerFormatErofs, "zstd", 0, false, false},
		// Rejected: unknown option key.
		{"erofs+zstd,foo=bar", LayerFormatErofs, "zstd", 0, false, false},
		// Rejected: unknown key alongside a valid level.
		{"erofs+zstd,level=3,foo=bar", LayerFormatErofs, "zstd", 3, true, false},
		// Rejected: bare option with no '='.
		{"erofs+zstd,solo", LayerFormatErofs, "zstd", 0, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.spec, func(t *testing.T) {
			f := LayerFormat(tt.spec)
			if got := f.Base(); got != tt.wantBase {
				t.Errorf("Base: got %q, want %q", got, tt.wantBase)
			}
			if got := f.Compressor(); got != tt.wantComp {
				t.Errorf("Compressor: got %q, want %q", got, tt.wantComp)
			}
			lvl, has := f.CompressionLevel()
			if has != tt.wantHasLvl || lvl != tt.wantLevel {
				t.Errorf("CompressionLevel: got (%d, %v), want (%d, %v)", lvl, has, tt.wantLevel, tt.wantHasLvl)
			}
			if got := f.Valid(); got != tt.wantValid {
				t.Errorf("Valid: got %v, want %v", got, tt.wantValid)
			}
		})
	}
}
