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
	"maps"
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

// TestWithAnnotationsOrderIndependent pins that WithAnnotations merges into,
// and takes precedence over, the configured annotations regardless of where it
// appears relative to WithImageConfiguration.
func TestWithAnnotationsOrderIndependent(t *testing.T) {
	override := map[string]string{"a": "override", "b": "added"}
	configured := func() types.ImageConfiguration {
		return types.ImageConfiguration{Annotations: map[string]string{"a": "configured", "c": "kept"}}
	}

	for _, tc := range []struct {
		name string
		opts []Option
		want map[string]string
	}{{
		name: "override before config",
		opts: []Option{WithAnnotations(override), WithImageConfiguration(configured())},
		want: map[string]string{"a": "override", "b": "added", "c": "kept"},
	}, {
		name: "override after config",
		opts: []Option{WithImageConfiguration(configured()), WithAnnotations(override)},
		want: map[string]string{"a": "override", "b": "added", "c": "kept"},
	}, {
		name: "no override leaves configured annotations",
		opts: []Option{WithImageConfiguration(configured())},
		want: map[string]string{"a": "configured", "c": "kept"},
	}, {
		name: "empty override leaves configured annotations",
		opts: []Option{WithAnnotations(nil), WithImageConfiguration(configured())},
		want: map[string]string{"a": "configured", "c": "kept"},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			_, ic, err := NewOptions(tc.opts...)
			if err != nil {
				t.Fatalf("NewOptions: %v", err)
			}
			if !maps.Equal(ic.Annotations, tc.want) {
				t.Errorf("Annotations = %v, want %v", ic.Annotations, tc.want)
			}
		})
	}
}

// TestWithAnnotationsDoesNotMutateCaller checks that resolving the annotations
// leaves the ImageConfiguration the caller handed to WithImageConfiguration
// alone; ic is copied by value but its Annotations map is not.
func TestWithAnnotationsDoesNotMutateCaller(t *testing.T) {
	caller := types.ImageConfiguration{Annotations: map[string]string{"a": "configured"}}

	if _, _, err := NewOptions(
		WithImageConfiguration(caller),
		WithAnnotations(map[string]string{"a": "override", "b": "added"}),
	); err != nil {
		t.Fatalf("NewOptions: %v", err)
	}

	want := map[string]string{"a": "configured"}
	if !maps.Equal(caller.Annotations, want) {
		t.Errorf("caller annotations mutated: got %v, want %v", caller.Annotations, want)
	}
}

func TestWithFormatInvalid(t *testing.T) {
	if _, _, err := NewOptions(WithFormat("squashfs")); err == nil {
		t.Error("NewOptions(WithFormat(\"squashfs\")) = nil error, want an error")
	}
}
