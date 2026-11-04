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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"log/slog"
	"testing"

	"github.com/chainguard-dev/clog"
	"github.com/stretchr/testify/require"
)

func TestSortSignaturesByStrength(t *testing.T) {
	sigs := []Signature{
		{KeyID: "sha1-first", DigestAlgorithm: crypto.SHA1},
		{KeyID: "sha256-first", DigestAlgorithm: crypto.SHA256},
		{KeyID: "sha1-second", DigestAlgorithm: crypto.SHA1},
		{KeyID: "sha256-second", DigestAlgorithm: crypto.SHA256},
	}

	sortSignaturesByStrength(sigs)

	got := make([]string, 0, len(sigs))
	for _, s := range sigs {
		got = append(got, s.KeyID)
	}
	// SHA-256 signatures are tried before SHA-1 ones; ties keep index order.
	require.Equal(t, []string{"sha256-first", "sha256-second", "sha1-first", "sha1-second"}, got)
}

// signTestIndexWith prepends a signature segment carrying one entry per
// (name, digest) pair, each a PKCS#1 v1.5 signature over index by key.
// corrupt names the entries whose signature bytes are flipped.
func signTestIndexWith(t *testing.T, key testIndexKey, index []byte, entries []crypto.Hash, corrupt map[crypto.Hash]bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for _, h := range entries {
		hh := h.New()
		_, _ = hh.Write(index)
		sig, err := rsa.SignPKCS1v15(rand.Reader, key.priv, h, hh.Sum(nil))
		require.NoError(t, err)
		if corrupt[h] {
			sig[len(sig)/2] ^= 0xff
		}
		prefix := map[crypto.Hash]string{crypto.SHA1: ".SIGN.RSA.", crypto.SHA256: ".SIGN.RSA256."}[h]
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: prefix + key.name, Mode: 0o644, Size: int64(len(sig))}))
		_, err = tw.Write(sig)
		require.NoError(t, err)
	}
	require.NoError(t, tw.Flush())
	require.NoError(t, gw.Close())
	return append(buf.Bytes(), index...)
}

// TestVerifyIndexSignatureOrder checks the property behind the sort: an
// RSA256 signature is tried first and verifies silently, and a legacy
// RSA/SHA-1 signature is only relied on, with a warning, when nothing
// stronger verifies.
func TestVerifyIndexSignatureOrder(t *testing.T) {
	key := newTestIndexKey(t)
	keys := map[string][]byte{key.name: key.pub}
	index := unsignedTestIndex(t, scanTestPackages(2))
	const u = "https://example.invalid/x86_64/APKINDEX.tar.gz"

	for name, tc := range map[string]struct {
		entries  []crypto.Hash
		corrupt  map[crypto.Hash]bool
		wantErr  bool
		wantWarn bool
	}{
		"rsa256 only":                {entries: []crypto.Hash{crypto.SHA256}},
		"sha1 listed first, both ok": {entries: []crypto.Hash{crypto.SHA1, crypto.SHA256}},
		"sha1 only":                  {entries: []crypto.Hash{crypto.SHA1}, wantWarn: true},
		"rsa256 corrupt, sha1 ok":    {entries: []crypto.Hash{crypto.SHA256, crypto.SHA1}, corrupt: map[crypto.Hash]bool{crypto.SHA256: true}, wantWarn: true},
		"both corrupt":               {entries: []crypto.Hash{crypto.SHA256, crypto.SHA1}, corrupt: map[crypto.Hash]bool{crypto.SHA256: true, crypto.SHA1: true}, wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			var logs bytes.Buffer
			ctx := clog.WithLogger(context.Background(), clog.New(slog.NewTextHandler(&logs, nil)))

			signed := signTestIndexWith(t, key, index, tc.entries, tc.corrupt)
			offset, err := verifyIndexSignature(ctx, u, keys, "x86_64", signed, &indexOpts{})
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, index, signed[offset:], "the verified offset starts the index segment")
			if tc.wantWarn {
				require.Contains(t, logs.String(), "legacy RSA/SHA-1 signature")
			} else {
				require.NotContains(t, logs.String(), "RSA/SHA-1", "a verified RSA256 signature must not warn about SHA-1")
			}
		})
	}
}
