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
	"bytes"
	"cmp"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"

	"go.opentelemetry.io/otel"

	"chainguard.dev/apko/pkg/build/types"
)

// Directory apk reads trusted signing keys from. Keys placed here let runtime
// `apk add` verify packages from runtime repositories.
const apkKeysDir = "etc/apk/keys"

// installSigningKeys writes the image configuration's inline APK signing public
// keys to /etc/apk/keys. It runs after package installation (post-FixateWorld),
// so the keys are a runtime trust anchor only and never participate in build-time
// package resolution.
//
// Keys are content-bearing in the config (like certificates), so the build stays
// reproducible: identical key content and names produce identical output, with no
// host paths leaking into the image or the locked configuration.
func (bc *Context) installSigningKeys(ctx context.Context) error {
	_, span := otel.Tracer("apko").Start(ctx, "installSigningKeys")
	defer span.End()

	if bc.ic.SigningKeys == nil || len(bc.ic.SigningKeys.Additional) == 0 {
		return nil
	}

	builtTime, err := bc.GetBuildDateEpoch()
	if err != nil {
		return fmt.Errorf("failed to get build date epoch: %w", err)
	}

	if err := bc.fs.MkdirAll(apkKeysDir, 0o755); err != nil {
		return fmt.Errorf("failed to create apk keys directory: %w", err)
	}

	// Sort by name so the write order is deterministic regardless of config
	// ordering.
	keys := slices.Clone(bc.ic.SigningKeys.Additional)
	slices.SortFunc(keys, func(a, b types.AdditionalSigningKeyEntry) int {
		return cmp.Compare(a.Name, b.Name)
	})

	for _, key := range keys {
		encoded, err := parseSigningKey(key.Content)
		if err != nil {
			return fmt.Errorf("failed to parse signing key %q: %w", key.Name, err)
		}

		// Name is validated against certNameRegex during configuration
		// validation, so it can't escape the directory.
		keyPath := filepath.Join(apkKeysDir, key.Name)

		// Refuse to overwrite an existing key. By this point InitKeyring has
		// already installed the distro trust roots (e.g. wolfi-signing.rsa.pub),
		// so a name collision would silently replace a packaged key and change
		// runtime verification behaviour.
		//
		// Note: on base-image builds inherited keys live in a lower layer, not
		// bc.fs, so this only catches collisions within the layer being built.
		if _, err := bc.fs.Stat(keyPath); err == nil {
			return fmt.Errorf("signing key %q collides with an existing /etc/apk/keys entry", key.Name)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("failed to stat %s: %w", keyPath, err)
		}

		if err := bc.fs.WriteFile(keyPath, encoded, 0o644); err != nil {
			return fmt.Errorf("failed to write signing key %s: %w", keyPath, err)
		}
		if err := bc.fs.Chtimes(keyPath, builtTime, builtTime); err != nil {
			return fmt.Errorf("failed to change times on signing key %s: %w", keyPath, err)
		}
	}

	return nil
}

// parseSigningKey validates that pemData is exactly one PEM-encoded RSA public
// key and returns it re-encoded. Re-encoding drops any trailing bytes around the
// block, keeping the written file canonical and reproducible.
func parseSigningKey(pemData string) ([]byte, error) {
	if pemData == "" {
		return nil, fmt.Errorf("no key data provided")
	}

	block, rest := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("expected PUBLIC KEY block, got %s", block.Type)
	}
	if next, _ := pem.Decode(rest); next != nil {
		return nil, fmt.Errorf("multiple PEM blocks found; only one is allowed")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	if _, ok := pub.(*rsa.PublicKey); !ok {
		return nil, fmt.Errorf("expected an RSA public key, got %T", pub)
	}

	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "PUBLIC KEY", Bytes: block.Bytes}); err != nil {
		return nil, fmt.Errorf("failed to re-encode public key: %w", err)
	}
	return buf.Bytes(), nil
}
