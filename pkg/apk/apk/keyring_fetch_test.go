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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
)

// TestInitKeyringRejectsBadRemoteKeys covers the checks a key fetched over
// HTTP must pass before it is written into /etc/apk/keys: a size limit and
// a parse as a PEM RSA public key.
func TestInitKeyringRejectsBadRemoteKeys(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecDER, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	require.NoError(t, err)
	ecPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ecDER})

	for _, tc := range []struct {
		name    string
		body    []byte
		wantErr string
	}{{
		name:    "oversized body",
		body:    bytes.Repeat([]byte("A"), int(maxKeySize)+1),
		wantErr: "larger than",
	}, {
		name:    "not PEM",
		body:    []byte("<html>not a key</html>"),
		wantErr: "no PEM block",
	}, {
		name:    "PEM but not RSA",
		body:    ecPEM,
		wantErr: "expected RSA",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(tc.body)
			}))
			defer s.Close()

			src := apkfs.NewMemFS()
			a, err := New(t.Context(), WithFS(src), WithIgnoreMknodErrors(ignoreMknodErrors))
			require.NoError(t, err)

			err = a.InitKeyring(t.Context(), []string{s.URL + "/bad.rsa.pub"}, nil)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.wantErr)

			_, err = src.Stat(DefaultKeyRingPath + "/bad.rsa.pub")
			require.Error(t, err, "rejected key must not be written to the keyring")
		})
	}

	// A valid key is accepted both at its natural size and padded to exactly
	// the limit (pem.Decode ignores what follows the block), so the cap is
	// "larger than", not "at least".
	atLimit := append([]byte(testDemoKey), bytes.Repeat([]byte("\n"), int(maxKeySize)-len(testDemoKey))...)
	require.Len(t, atLimit, int(maxKeySize))
	for name, body := range map[string][]byte{
		"valid key is accepted":              []byte(testDemoKey),
		"valid key at the limit is accepted": atLimit,
	} {
		t.Run(name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(body)
			}))
			defer s.Close()

			src := apkfs.NewMemFS()
			a, err := New(t.Context(), WithFS(src), WithIgnoreMknodErrors(ignoreMknodErrors))
			require.NoError(t, err)

			require.NoError(t, a.InitKeyring(t.Context(), []string{s.URL + "/good.rsa.pub"}, nil))
			got, err := src.ReadFile(DefaultKeyRingPath + "/good.rsa.pub")
			require.NoError(t, err)
			require.Equal(t, body, got)
		})
	}
}
