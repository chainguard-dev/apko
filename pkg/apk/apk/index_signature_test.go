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

package apk

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"testing"

	"chainguard.dev/apko/internal/sha1cd"
	"chainguard.dev/apko/internal/sha1cd/sha1cdtest"
	sign "chainguard.dev/apko/pkg/apk/signature"
)

func TestHashIndex(t *testing.T) {
	// Digests must be unchanged from crypto/sha1 and crypto/sha256, or every
	// existing signature over an index would stop verifying.
	for _, tc := range []struct {
		algorithm crypto.Hash
		want      string
	}{
		{crypto.SHA1, "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"},
		{crypto.SHA256, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"},
	} {
		digest, err := hashIndex(tc.algorithm, []byte("hello world"))
		if err != nil {
			t.Errorf("hashIndex(%s): %v", tc.algorithm, err)
			continue
		}
		if got := hex.EncodeToString(digest); got != tc.want {
			t.Errorf("hashIndex(%s) = %s, want %s", tc.algorithm, got, tc.want)
		}
	}
}

// An index built around a SHA-1 collision must be refused before its digest can
// be handed to signature verification.
func TestHashIndexRejectsCollision(t *testing.T) {
	digest, err := hashIndex(crypto.SHA1, sha1cdtest.Shattered(t))
	if !errors.Is(err, sha1cd.ErrCollision) {
		t.Errorf("hashIndex = %x, %v; want ErrCollision", digest, err)
	}
	if digest != nil {
		t.Errorf("hashIndex returned a digest %x alongside the error", digest)
	}
}

func TestHashIndexUnsupportedAlgorithm(t *testing.T) {
	if _, err := hashIndex(crypto.SHA512, []byte("hello world")); err == nil {
		t.Error("hashIndex(SHA512) = nil error, want an unsupported algorithm error")
	}
}

// Verifying legacy RSA/SHA-1 index signatures must keep working now that apko no
// longer registers crypto.SHA1 in the crypto hash registry.
func TestVerifyLegacySHA1IndexSignature(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshalling public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	indexData := []byte("C:Q1eVchkwzRw6t2f8kNKDIcm/6DrE0=\nP:apko\nV:1.0.0\n")
	digest, err := hashIndex(crypto.SHA1, indexData)
	if err != nil {
		t.Fatalf("hashing index: %v", err)
	}

	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, digest)
	if err != nil {
		t.Fatalf("signing index: %v", err)
	}

	if err := sign.RSAVerifyDigest(digest, crypto.SHA1, signature, pubPEM); err != nil {
		t.Errorf("RSAVerifyDigest(SHA1) = %v, want nil", err)
	}

	// And a signature over different data must still be rejected.
	otherDigest, err := hashIndex(crypto.SHA1, append(indexData, '\n'))
	if err != nil {
		t.Fatalf("hashing index: %v", err)
	}
	if err := sign.RSAVerifyDigest(otherDigest, crypto.SHA1, signature, pubPEM); err == nil {
		t.Error("RSAVerifyDigest accepted a signature over different index data")
	}
}
