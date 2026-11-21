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
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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

// TestInitKeyringContentDisposition covers keys served from a URL that does
// not carry the key's name, which is instead given in a Content-Disposition
// header, as Gitea and Forgejo package registries do.
func TestInitKeyringContentDisposition(t *testing.T) {
	const keyName = "test@5c6bb80ae094a76863d00718d8ff0fc208ae441d0e3e302d29d185b929eea22c.rsa.pub"

	for _, tc := range []struct {
		name               string
		path               string
		contentDisposition string
		want               string
	}{{
		// What Gitea and Forgejo send: the extended value is not percent-encoded.
		name:               "forgejo header",
		path:               "/api/packages/owner/alpine/key",
		contentDisposition: `attachment; filename="` + keyName + `"; filename*=UTF-8''` + keyName,
		want:               keyName,
	}, {
		name:               "extended filename takes precedence",
		path:               "/api/packages/owner/alpine/key",
		contentDisposition: `attachment; filename="fallback.rsa.pub"; filename*=UTF-8''` + strings.Replace(keyName, "@", "%40", 1),
		want:               keyName,
	}, {
		name:               "unencoded extended filename falls back to filename",
		path:               "/api/packages/owner/alpine/key",
		contentDisposition: `attachment; filename*=UTF-8''ignored@example.rsa.pub; filename="` + keyName + `"`,
		want:               keyName,
	}, {
		name:               "quoted semicolon in filename",
		path:               "/api/packages/owner/alpine/key",
		contentDisposition: `attachment; filename="a;b@example.rsa.pub"; filename*=UTF-8''a%3Bb@example.rsa.pub`,
		want:               "a;b@example.rsa.pub",
	}, {
		name:               "unencoded extended filename alone uses the URL",
		path:               "/api/packages/owner/alpine/key",
		contentDisposition: `attachment; filename*=UTF-8''` + keyName,
		want:               "key",
	}, {
		name:               "filename restores a missing extension",
		path:               "/artifactory/keys/alpine-devel@lists.alpinelinux.org-4a6a0840",
		contentDisposition: `attachment; filename="alpine-devel@lists.alpinelinux.org-4a6a0840.rsa.pub"`,
		want:               "alpine-devel@lists.alpinelinux.org-4a6a0840.rsa.pub",
	}, {
		name: "no header uses the URL",
		path: "/keys/good.rsa.pub",
		want: "good.rsa.pub",
	}, {
		name:               "no filename uses the URL",
		path:               "/keys/good.rsa.pub",
		contentDisposition: "inline",
		want:               "good.rsa.pub",
	}, {
		name:               "malformed header uses the URL",
		path:               "/api/packages/owner/alpine/key",
		contentDisposition: `attachment; filename="unterminated`,
		want:               "key",
	}, {
		name:               "path in filename uses the URL",
		path:               "/api/packages/owner/alpine/key",
		contentDisposition: `attachment; filename="../../../etc/evil.rsa.pub"`,
		want:               "key",
	}, {
		name:               "dot dot filename uses the URL",
		path:               "/api/packages/owner/alpine/key",
		contentDisposition: `attachment; filename=".."`,
		want:               "key",
	}, {
		name:               "empty filename uses the URL",
		path:               "/api/packages/owner/alpine/key",
		contentDisposition: `attachment; filename=""`,
		want:               "key",
	}} {
		// The cached client answers from its cache with a response of its own,
		// so it must carry the header over from the server's response.
		for _, cached := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s cached=%t", tc.name, cached), func(t *testing.T) {
				s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != tc.path {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					w.Header().Set("ETag", `"key-etag"`)
					if tc.contentDisposition != "" {
						w.Header().Set("Content-Disposition", tc.contentDisposition)
					}
					if r.Method == http.MethodHead {
						return
					}
					_, _ = w.Write([]byte(testDemoKey))
				}))
				defer s.Close()

				src := apkfs.NewMemFS()
				opts := []Option{WithFS(src), WithIgnoreMknodErrors(ignoreMknodErrors)}
				if cached {
					opts = append(opts, WithCache(t.TempDir(), false, NewCache(true)))
				}
				a, err := New(t.Context(), opts...)
				require.NoError(t, err)

				require.NoError(t, a.InitKeyring(t.Context(), []string{s.URL + tc.path}, nil))

				entries, err := src.ReadDir(DefaultKeyRingPath)
				require.NoError(t, err)
				require.Len(t, entries, 1, "expected exactly one key in the keyring")
				require.Equal(t, tc.want, entries[0].Name())
				got, err := src.ReadFile(DefaultKeyRingPath + "/" + tc.want)
				require.NoError(t, err)
				require.Equal(t, testDemoKey, string(got))
			})
		}
	}
}

// TestContentDispositionKeyVerifiesIndex checks that a key named only by its
// Content-Disposition header verifies an index signed with that key, as with a
// Forgejo package registry, which also refuses HEAD for the key.
func TestContentDispositionKeyVerifiesIndex(t *testing.T) {
	const keyName = "alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub"

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/key" && r.Method == http.MethodHead:
			w.WriteHeader(http.StatusMethodNotAllowed)
		case r.URL.Path == "/key":
			w.Header().Set("Content-Disposition", `attachment; filename="`+keyName+`"; filename*=UTF-8''`+keyName)
			_, _ = w.Write([]byte(strings.TrimSpace(testKeys[keyName])))
		default:
			r.URL.Path = strings.TrimPrefix(r.URL.Path, "/x86_64")
			http.FileServer(http.Dir(testPrimaryPkgDir)).ServeHTTP(w, r)
		}
	}))
	defer s.Close()

	ctx := t.Context()
	for _, cached := range []bool{false, true} {
		t.Run(fmt.Sprintf("cached=%t", cached), func(t *testing.T) {
			opts := []Option{WithFS(apkfs.NewMemFS()), WithArch("x86_64")}
			if cached {
				opts = append(opts, WithCache(t.TempDir(), false, NewCache(true)))
			}
			a, err := New(ctx, opts...)
			require.NoError(t, err)
			require.NoError(t, a.InitDB(ctx))
			require.NoError(t, a.InitKeyring(ctx, []string{s.URL + "/key"}, nil))
			require.NoError(t, a.SetRepositories(ctx, []string{s.URL}))

			indexes, err := a.GetRepositoryIndexes(ctx, false)
			require.NoError(t, err, "index signature should verify with the fetched key")
			require.Len(t, indexes, 1)
		})
	}
}
