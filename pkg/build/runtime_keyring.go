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
// `apk add` verify packages from runtime repositories. We are using these for
// fs.FS so should omit the leading /
const apkKeysDir = "etc/apk/keys"

// installInlineKeys writes inline {name, content} public keys into /etc/apk/keys
// in a deterministic order, refusing to overwrite an existing entry, and returns
// the paths written. It is the shared core of two callers: the build keyring
// (contents.keyring, installed before FixateWorld so it can verify build-repo
// signatures) and the runtime keyring (contents.runtime_keyring, installed
// after). Keys are content-bearing in the config, so the build stays
// reproducible — identical content and names produce identical output, with no
// host paths leaking into the image or the locked configuration.
func (bc *Context) installInlineKeys(keys []types.KeyEntry) ([]string, error) {
	if len(keys) == 0 {
		return nil, nil
	}

	if err := bc.fs.MkdirAll(apkKeysDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create apk keys directory: %w", err)
	}

	// Sort for a deterministic write order, then drop exact duplicates (an
	// included config can contribute the same key twice via MergeInto's concat).
	// Distinct keys with the same name remain and trip the collision check below.
	keys = slices.Clone(keys)
	slices.SortFunc(keys, types.CompareKeyEntry)
	keys = slices.CompactFunc(keys, func(a, b types.KeyEntry) bool { return a == b })

	written := make([]string, 0, len(keys))
	for _, key := range keys {
		encoded, err := parsePublicKey(key.Content)
		if err != nil {
			return nil, fmt.Errorf("failed to parse keyring entry %q: %w", key.Name, err)
		}

		// Name is validated against certNameRegex during configuration
		// validation, so it can't escape the directory.
		keyPath := filepath.Join(apkKeysDir, key.Name)

		// Refuse to overwrite an existing key: a name collision would silently
		// replace a packaged or already-installed key (e.g. wolfi-signing.rsa.pub)
		// and change verification behaviour.
		//
		// Note: on base-image builds inherited keys live in a lower layer, not
		// bc.fs, so this only catches collisions within the layer being built.
		if _, err := bc.fs.Stat(keyPath); err == nil {
			return nil, fmt.Errorf("keyring entry %q collides with an existing /etc/apk/keys entry", key.Name)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("failed to stat %s: %w", keyPath, err)
		}

		if err := bc.fs.WriteFile(keyPath, encoded, 0o644); err != nil {
			return nil, fmt.Errorf("failed to write keyring entry %s: %w", keyPath, err)
		}
		written = append(written, keyPath)
	}

	return written, nil
}

// installRuntimeKeyring writes contents.runtime_keyring's inline public keys to
// /etc/apk/keys. It runs after package installation (post-FixateWorld), so the
// keys are a runtime trust anchor only and never participate in build-time
// package resolution. URI-form entries are rejected during Validate
// (inline-first); this installer only sees inline keys.
func (bc *Context) installRuntimeKeyring(ctx context.Context) error {
	_, span := otel.Tracer("apko").Start(ctx, "installRuntimeKeyring")
	defer span.End()

	written, err := bc.installInlineKeys(bc.ic.Contents.RuntimeKeyring)
	if err != nil {
		return err
	}
	if len(written) == 0 {
		return nil
	}

	// Runtime keys are written after FixateWorld, where the build epoch is final;
	// pin their mtime to it so the image stays reproducible.
	builtTime, err := bc.GetBuildDateEpoch()
	if err != nil {
		return fmt.Errorf("failed to get build date epoch: %w", err)
	}
	for _, keyPath := range written {
		if err := bc.fs.Chtimes(keyPath, builtTime, builtTime); err != nil {
			return fmt.Errorf("failed to change times on runtime keyring entry %s: %w", keyPath, err)
		}
	}

	return nil
}

// parsePublicKey validates that pemData is exactly one PEM-encoded RSA public
// key and returns it re-encoded. Re-encoding drops any trailing bytes around the
// block, keeping the written file canonical and reproducible.
func parsePublicKey(pemData string) ([]byte, error) {
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
