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

package build

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/options"

	"github.com/google/go-cmp/cmp"
)

// rsaPublicKeyPEM returns a PEM-encoded ("PUBLIC KEY") RSA public key.
func rsaPublicKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshaling RSA public key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func ecPublicKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating EC key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshaling EC public key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func TestInstallSigningKeys(t *testing.T) {
	epoch := time.Unix(1337, 0)
	keyPEM := rsaPublicKeyPEM(t)

	tests := []struct {
		name string
		cfg  *types.ImageSigningKeys
		// existing files pre-populated under /etc/apk/keys, modelling keys
		// InitKeyring installed before installSigningKeys runs.
		existing map[string][]byte
		wantErr  bool
		wantKeys []string // basenames expected under /etc/apk/keys
	}{{
		name: "nil config is a no-op",
		cfg:  nil,
	}, {
		name:     "empty additional is a no-op",
		cfg:      &types.ImageSigningKeys{},
		wantKeys: nil,
	}, {
		name: "writes a single key",
		cfg: &types.ImageSigningKeys{Additional: []types.AdditionalSigningKeyEntry{
			{Name: "mirror.rsa.pub", Content: keyPEM},
		}},
		wantKeys: []string{"mirror.rsa.pub"},
	}, {
		name: "writes alongside an existing distro key",
		cfg: &types.ImageSigningKeys{Additional: []types.AdditionalSigningKeyEntry{
			{Name: "mirror.rsa.pub", Content: keyPEM},
		}},
		existing: map[string][]byte{
			filepath.Join(apkKeysDir, "wolfi-signing.rsa.pub"): []byte("existing-distro-key"),
		},
		wantKeys: []string{"mirror.rsa.pub", "wolfi-signing.rsa.pub"},
	}, {
		name: "refuses to overwrite an existing key",
		cfg: &types.ImageSigningKeys{Additional: []types.AdditionalSigningKeyEntry{
			{Name: "wolfi-signing.rsa.pub", Content: keyPEM},
		}},
		existing: map[string][]byte{
			filepath.Join(apkKeysDir, "wolfi-signing.rsa.pub"): []byte("existing-distro-key"),
		},
		wantErr: true,
	}, {
		name: "rejects a non-RSA key",
		cfg: &types.ImageSigningKeys{Additional: []types.AdditionalSigningKeyEntry{
			{Name: "ec.rsa.pub", Content: ecPublicKeyPEM(t)},
		}},
		wantErr: true,
	}, {
		name: "rejects malformed PEM",
		cfg: &types.ImageSigningKeys{Additional: []types.AdditionalSigningKeyEntry{
			{Name: "bad.rsa.pub", Content: "not a pem block"},
		}},
		wantErr: true,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("SOURCE_DATE_EPOCH", fmt.Sprintf("%d", epoch.Unix()))
			fsys := apkfs.NewMemFS()
			for path, content := range tt.existing {
				if err := fsys.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatalf("mkdir for existing %s: %v", path, err)
				}
				if err := fsys.WriteFile(path, content, 0o644); err != nil {
					t.Fatalf("write existing %s: %v", path, err)
				}
			}

			bc := &Context{
				o:  options.Options{SourceDateEpoch: epoch},
				ic: types.ImageConfiguration{SigningKeys: tt.cfg},
				fs: fsys,
			}

			err := bc.installSigningKeys(t.Context())
			if (err != nil) != tt.wantErr {
				t.Fatalf("installSigningKeys() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			for _, name := range tt.wantKeys {
				path := filepath.Join(apkKeysDir, name)
				stat, err := fsys.Stat(path)
				if err != nil {
					t.Fatalf("expected key %s: %v", path, err)
				}
				// Distro keys placed by setup keep their original mtime; only
				// installed customer keys get the deterministic epoch.
				if _, isCustomer := tt.existing[path]; !isCustomer {
					if mode := stat.Mode().Perm(); mode != 0o644 {
						t.Errorf("key %s mode = %v, want 0644", name, mode)
					}
					if !stat.ModTime().Equal(epoch) {
						t.Errorf("key %s mtime = %v, want %v", name, stat.ModTime(), epoch)
					}
				}
			}
		})
	}
}

// Customer keys are content-bearing and written deterministically, so two runs
// with identical input produce byte-identical files.
func TestInstallSigningKeysDeterministic(t *testing.T) {
	epoch := time.Unix(1337, 0)
	keyPEM := rsaPublicKeyPEM(t)
	cfg := &types.ImageSigningKeys{Additional: []types.AdditionalSigningKeyEntry{
		{Name: "b.rsa.pub", Content: keyPEM},
		{Name: "a.rsa.pub", Content: keyPEM},
	}}

	run := func() map[string][]byte {
		t.Setenv("SOURCE_DATE_EPOCH", fmt.Sprintf("%d", epoch.Unix()))
		fsys := apkfs.NewMemFS()
		bc := &Context{
			o:  options.Options{SourceDateEpoch: epoch},
			ic: types.ImageConfiguration{SigningKeys: cfg},
			fs: fsys,
		}
		if err := bc.installSigningKeys(t.Context()); err != nil {
			t.Fatalf("installSigningKeys: %v", err)
		}
		out := map[string][]byte{}
		for _, name := range []string{"a.rsa.pub", "b.rsa.pub"} {
			data, err := fsys.ReadFile(filepath.Join(apkKeysDir, name))
			if err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			out[name] = data
		}
		return out
	}

	if diff := cmp.Diff(run(), run()); diff != "" {
		t.Errorf("non-deterministic output (-run1 +run2):\n%s", diff)
	}
}

func TestParseSigningKey(t *testing.T) {
	keyPEM := rsaPublicKeyPEM(t)

	tests := []struct {
		name    string
		content string
		wantErr bool
	}{
		{name: "valid RSA public key", content: keyPEM},
		{name: "empty", content: "", wantErr: true},
		{name: "not a PEM block", content: "garbage", wantErr: true},
		{name: "EC key rejected", content: ecPublicKeyPEM(t), wantErr: true},
		{name: "certificate block rejected", content: testCertPEM, wantErr: true},
		{name: "multiple blocks rejected", content: keyPEM + keyPEM, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSigningKey(tt.content)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseSigningKey() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if block, _ := pem.Decode(got); block == nil || block.Type != "PUBLIC KEY" {
				t.Errorf("re-encoded output is not a PUBLIC KEY PEM block")
			}
		})
	}
}

// Re-encoding canonicalizes the key: trailing text around the block is dropped.
func TestParseSigningKeyDropsTrailingBytes(t *testing.T) {
	keyPEM := rsaPublicKeyPEM(t)
	got, err := parseSigningKey(keyPEM + "\ntrailing junk that is not pem\n")
	if err != nil {
		t.Fatalf("parseSigningKey: %v", err)
	}
	if strings.Contains(string(got), "trailing junk") {
		t.Errorf("re-encoded key retained trailing bytes:\n%s", got)
	}
}

// The DoD invariant: inline signing keys are content-addressed. The serialized
// configuration carries the key content (so identity is reproducible) but never
// a host path, temp dir, or file:// URI.
func TestSigningKeysSerializationCarriesContentNotPath(t *testing.T) {
	keyPEM := rsaPublicKeyPEM(t)
	ic := types.ImageConfiguration{
		SigningKeys: &types.ImageSigningKeys{Additional: []types.AdditionalSigningKeyEntry{
			{Name: "mirror.rsa.pub", Content: keyPEM},
		}},
	}

	a, err := json.Marshal(ic)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	b, err := json.Marshal(ic)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(a) != string(b) {
		t.Errorf("identical configs marshaled differently:\n%s\n%s", a, b)
	}

	s := string(a)
	if !strings.Contains(s, "signing_keys") || !strings.Contains(s, "BEGIN PUBLIC KEY") {
		t.Errorf("serialized config missing signing key content:\n%s", s)
	}
	for _, banned := range []string{"file://", "/tmp/", "/etc/apk/keys", string(filepath.Separator) + "var" + string(filepath.Separator)} {
		if strings.Contains(s, banned) {
			t.Errorf("serialized config leaked a path substring %q:\n%s", banned, s)
		}
	}
}
