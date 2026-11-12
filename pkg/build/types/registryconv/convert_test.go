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

package registryconv

import (
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	fuzz "github.com/google/gofuzz"
	"google.golang.org/protobuf/testing/protocmp"

	apkotypes "chainguard.dev/apko/pkg/build/types"
)

// TestRoundTrip tests that converting an ImageConfiguration to protobuf and back
// yields the original ImageConfiguration, and vice versa, modulo ignored fields.
func TestRoundTrip(t *testing.T) {
	if err := quick.Check(func(apko apkotypes.ImageConfiguration) bool {
		pb := ToApkoProto(apko)
		apko2 := ToApkoNative(pb)
		// Include was deprecated in the proto.
		// BaseImage is not supported in the registry proto.
		// RuntimeKeyring is deliberately absent from ApkoConfig: customer
		// signing keys ride CustomOverlay.contents.runtime_keyring, never the
		// raw apko service surface.
		// Format (apko v1.2.38+) is not supported either: the build service
		// only emits tar layers. TestFormatIsDropped pins that.
		// We ignore them here to avoid the diff.
		// https://github.com/chainguard-dev/apko/blob/main/pkg/build/types/types.go#L185-L186
		if d := cmp.Diff(apko, apko2,
			cmpopts.IgnoreFields(apkotypes.ImageConfiguration{}, "Include", "Format"),
			cmpopts.IgnoreFields(apkotypes.ImageContents{}, "BaseImage", "RuntimeKeyring")); d != "" {
			t.Errorf("apko diff(-want,+got): %s", d)
			return false
		}

		pb2 := ToApkoProto(apko2)
		if d := cmp.Diff(pb, pb2, protocmp.Transform()); d != "" {
			t.Errorf("proto diff(-want,+got): %s", d)
		}
		return true
	}, &quick.Config{
		Values: func(vals []reflect.Value, r *rand.Rand) {
			// Use gofuzz to generate random ImageConfiguration values
			fz := fuzz.NewWithSeed(r.Int63())
			fz.NilChance(0.2)
			fz.NumElements(1, 3)

			var apko apkotypes.ImageConfiguration
			fz.Fuzz(&apko)
			vals[0] = reflect.ValueOf(apko)
		},
	}); err != nil {
		t.Error(err)
	}
}

// TestFormatIsDropped pins the omission TestRoundTrip ignores: apko's layer
// format does not cross this boundary, so a config asking for erofs builds a
// tar layer rather than failing. Delete this test if ApkoConfig grows a format
// field.
func TestFormatIsDropped(t *testing.T) {
	in := apkotypes.ImageConfiguration{Format: apkotypes.LayerFormatErofs}
	if got := ToApkoNative(ToApkoProto(in)).Format; got != "" {
		t.Errorf("Format survived the round trip: got %q, want %q", got, "")
	}
}

// TestPathMutationPresence pins the uid/gid cases quick.Check essentially
// never samples (a zero pointee is one value in 2^32): nil and explicit 0
// are distinct — nil leaves ownership untouched, 0 chowns to root — and
// must survive the round trip distinctly.
func TestPathMutationPresence(t *testing.T) {
	zero, nonzero := uint32(0), uint32(65532)
	in := apkotypes.ImageConfiguration{Paths: []apkotypes.PathMutation{
		{Path: "/absent", Type: "permissions"},
		{Path: "/root", Type: "permissions", UID: &zero, GID: &zero},
		{Path: "/nonroot", Type: "permissions", UID: &nonzero, GID: &nonzero},
		{Path: "/mixed", Type: "permissions", UID: &zero},
	}}
	got := ToApkoNative(ToApkoProto(in))
	if d := cmp.Diff(in.Paths, got.Paths); d != "" {
		t.Errorf("paths round-trip (-want, +got): %s", d)
	}
}
