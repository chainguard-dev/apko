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

package build

import (
	"testing"

	"chainguard.dev/apko/pkg/build/types"
)

// TestWithFormatOrderIndependent pins that WithFormat survives a later
// WithImageConfiguration, which replaces the whole configuration.
func TestWithFormatOrderIndependent(t *testing.T) {
	configured := types.ImageConfiguration{Format: types.LayerFormatTar}

	for _, tc := range []struct {
		name string
		opts []Option
		want types.LayerFormat
	}{{
		name: "override before config",
		opts: []Option{WithFormat("erofs"), WithImageConfiguration(types.ImageConfiguration{})},
		want: types.LayerFormatErofs,
	}, {
		name: "override after config",
		opts: []Option{WithImageConfiguration(types.ImageConfiguration{}), WithFormat("erofs")},
		want: types.LayerFormatErofs,
	}, {
		name: "override beats configured value",
		opts: []Option{WithFormat("erofs"), WithImageConfiguration(configured)},
		want: types.LayerFormatErofs,
	}, {
		name: "empty override leaves configured value",
		opts: []Option{WithFormat(""), WithImageConfiguration(configured)},
		want: types.LayerFormatTar,
	}, {
		name: "no override leaves configured value",
		opts: []Option{WithImageConfiguration(configured)},
		want: types.LayerFormatTar,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			_, ic, err := NewOptions(tc.opts...)
			if err != nil {
				t.Fatalf("NewOptions: %v", err)
			}
			if ic.Format != tc.want {
				t.Errorf("Format = %q, want %q", ic.Format, tc.want)
			}
		})
	}
}

func TestWithFormatInvalid(t *testing.T) {
	if _, _, err := NewOptions(WithFormat("squashfs")); err == nil {
		t.Error("NewOptions(WithFormat(\"squashfs\")) = nil error, want an error")
	}
}
