// Copyright 2025 Chainguard, Inc.
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

package types_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gopkg.in/yaml.v3"

	"chainguard.dev/apko/pkg/build/types"
)

// TestRuntimeKeyringEntryStrictDecode mirrors the configuration loader's
// strict decoding (KnownFields, image_configuration.go): unknown keys inside
// a runtime_keyring entry must be rejected, and well-formed entries decode.
func TestRuntimeKeyringEntryStrictDecode(t *testing.T) {
	type holder struct {
		RuntimeKeyring []types.RuntimeKeyringEntry `yaml:"runtime_keyring"`
	}

	tests := []struct {
		name    string
		yaml    string
		want    []types.RuntimeKeyringEntry
		wantErr bool
	}{{
		name: "name and content decode",
		yaml: "runtime_keyring:\n  - name: mirror.rsa.pub\n    content: PEM",
		want: []types.RuntimeKeyringEntry{{Name: "mirror.rsa.pub", Content: "PEM"}},
	}, {
		name:    "unknown key rejected by strict decoding",
		yaml:    "runtime_keyring:\n  - name: mirror.rsa.pub\n    content: PEM\n    uri: https://example.com/k.rsa.pub",
		wantErr: true,
	}, {
		name:    "scalar entry rejected (no URI form)",
		yaml:    "runtime_keyring:\n  - https://example.com/k.rsa.pub",
		wantErr: true,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := yaml.NewDecoder(strings.NewReader(tt.yaml))
			dec.KnownFields(true)
			var h holder
			err := dec.Decode(&h)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Decode error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if diff := cmp.Diff(tt.want, h.RuntimeKeyring); diff != "" {
				t.Errorf("(-want +got):\n%s", diff)
			}
		})
	}
}

// The JSON wire shape feeds /etc/apko.json and the locked-config dedup key:
// entries must serialize as {name, content} objects carrying the key bytes.
func TestRuntimeKeyringEntryMarshalJSON(t *testing.T) {
	b, err := json.Marshal(types.ImageContents{
		RuntimeKeyring: []types.RuntimeKeyringEntry{{Name: "m.rsa.pub", Content: "PEM"}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"runtime_keyring":[{"name":"m.rsa.pub","content":"PEM"}]}`
	if got := string(b); got != want {
		t.Errorf("MarshalJSON\n got: %s\nwant: %s", got, want)
	}
}

// MergeInto must concat RuntimeKeyring — it is the path that builds the locked
// config (via input.MergeInto) and merges includes, so omission silently drops
// the field from the dedup key and from include-derived builds.
func TestImageContentsMergeIntoRuntimeKeyring(t *testing.T) {
	source := types.ImageContents{RuntimeKeyring: []types.RuntimeKeyringEntry{{Name: "a.rsa.pub", Content: "A"}}}
	target := types.ImageContents{RuntimeKeyring: []types.RuntimeKeyringEntry{{Name: "b.rsa.pub", Content: "B"}}}
	if err := source.MergeInto(&target); err != nil {
		t.Fatalf("MergeInto: %v", err)
	}
	want := []types.RuntimeKeyringEntry{{Name: "a.rsa.pub", Content: "A"}, {Name: "b.rsa.pub", Content: "B"}}
	if diff := cmp.Diff(want, target.RuntimeKeyring); diff != "" {
		t.Errorf("RuntimeKeyring not concatenated (-want +got):\n%s", diff)
	}
}
