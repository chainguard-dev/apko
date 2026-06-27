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
	"testing"

	"github.com/google/go-cmp/cmp"
	"gopkg.in/yaml.v3"

	"chainguard.dev/apko/pkg/build/types"
)

// holder mirrors how KeyEntry is used in a config: a list field.
type holder struct {
	Keyring []types.KeyEntry `yaml:"keyring" json:"keyring"`
}

func TestKeyEntryUnmarshalYAML(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		want    []types.KeyEntry
		wantErr bool
	}{
		{name: "scalar URI", yaml: `keyring: ["https://example.com/k.rsa.pub"]`,
			want: []types.KeyEntry{{URI: "https://example.com/k.rsa.pub"}}},
		{name: "scalar path", yaml: `keyring: ["./local.rsa.pub"]`,
			want: []types.KeyEntry{{URI: "./local.rsa.pub"}}},
		{name: "inline mapping", yaml: "keyring:\n  - name: mirror.rsa.pub\n    content: PEM",
			want: []types.KeyEntry{{Name: "mirror.rsa.pub", Content: "PEM"}}},
		{name: "mixed list", yaml: "keyring:\n  - https://example.com/k.rsa.pub\n  - {name: m.rsa.pub, content: PEM}",
			want: []types.KeyEntry{{URI: "https://example.com/k.rsa.pub"}, {Name: "m.rsa.pub", Content: "PEM"}}},
		{name: "unknown key rejected", yaml: "keyring:\n  - {name: m.rsa.pub, content: PEM, typo: x}", wantErr: true},
		{name: "numeric name rejected", yaml: "keyring:\n  - {name: 1, content: PEM}", wantErr: true},
		{name: "bool content rejected", yaml: "keyring:\n  - {name: m.rsa.pub, content: true}", wantErr: true},
		{name: "partial mapping (name only) rejected", yaml: "keyring:\n  - {name: m.rsa.pub}", wantErr: true},
		{name: "partial mapping (content only) rejected", yaml: "keyring:\n  - {content: PEM}", wantErr: true},
		{name: "wrong node kind (int) rejected", yaml: `keyring: [42]`, wantErr: true},
		{name: "wrong node kind (sequence) rejected", yaml: "keyring:\n  - [a, b]", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var h holder
			err := yaml.Unmarshal([]byte(tt.yaml), &h)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Unmarshal error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if diff := cmp.Diff(tt.want, h.Keyring); diff != "" {
				t.Errorf("(-want +got):\n%s", diff)
			}
		})
	}
}

func TestKeyEntryYAMLRoundTrip(t *testing.T) {
	in := holder{Keyring: []types.KeyEntry{
		{URI: "https://example.com/k.rsa.pub"},
		{Name: "mirror.rsa.pub", Content: "PEM"},
	}}
	b, err := yaml.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out holder
	if err := yaml.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if diff := cmp.Diff(in, out); diff != "" {
		t.Errorf("round-trip (-in +out):\n%s\nyaml:\n%s", diff, b)
	}
}

// MarshalJSON drives /etc/apko.json + the dedup key: URI -> string, inline ->
// {name, content}. (There is no UnmarshalJSON; config is parsed from YAML only.)
func TestKeyEntryMarshalJSON(t *testing.T) {
	h := holder{Keyring: []types.KeyEntry{
		{URI: "https://example.com/k.rsa.pub"},
		{Name: "m.rsa.pub", Content: "PEM"},
	}}
	b, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"keyring":["https://example.com/k.rsa.pub",{"content":"PEM","name":"m.rsa.pub"}]}`
	if got := string(b); got != want {
		t.Errorf("MarshalJSON\n got: %s\nwant: %s", got, want)
	}
}

// MergeInto must concat RuntimeKeyring — it is the path that builds the locked
// config (via input.MergeInto) and merges includes, so omission silently drops
// the field from the dedup key and from include-derived builds.
func TestImageContentsMergeIntoRuntimeKeyring(t *testing.T) {
	source := types.ImageContents{RuntimeKeyring: []types.KeyEntry{{Name: "a.rsa.pub", Content: "A"}}}
	target := types.ImageContents{RuntimeKeyring: []types.KeyEntry{{Name: "b.rsa.pub", Content: "B"}}}
	if err := source.MergeInto(&target); err != nil {
		t.Fatalf("MergeInto: %v", err)
	}
	want := []types.KeyEntry{{Name: "a.rsa.pub", Content: "A"}, {Name: "b.rsa.pub", Content: "B"}}
	if diff := cmp.Diff(want, target.RuntimeKeyring); diff != "" {
		t.Errorf("RuntimeKeyring not concatenated (-want +got):\n%s", diff)
	}
}
