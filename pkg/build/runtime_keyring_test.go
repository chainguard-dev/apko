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
	"archive/tar"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/apk/apk"
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

func inlineKey(name, content string) types.RuntimeKeyringEntry {
	return types.RuntimeKeyringEntry{Name: name, Content: content}
}

func TestInstallRuntimeKeyring(t *testing.T) {
	epoch := time.Unix(1337, 0)
	keyPEM := rsaPublicKeyPEM(t)

	tests := []struct {
		name string
		keys []types.RuntimeKeyringEntry
		// existing files under /etc/apk/keys, modelling keys InitKeyring
		// installed before installRuntimeKeyring runs.
		existing map[string][]byte
		wantErr  bool
		wantKeys []string // basenames expected under /etc/apk/keys
	}{{
		name: "empty is a no-op",
		keys: nil,
	}, {
		name:     "writes a single key",
		keys:     []types.RuntimeKeyringEntry{inlineKey("mirror.rsa.pub", keyPEM)},
		wantKeys: []string{"mirror.rsa.pub"},
	}, {
		name: "writes alongside an existing distro key",
		keys: []types.RuntimeKeyringEntry{inlineKey("mirror.rsa.pub", keyPEM)},
		existing: map[string][]byte{
			filepath.Join(apkKeysDir, "wolfi-signing.rsa.pub"): []byte("existing-distro-key"),
		},
		wantKeys: []string{"mirror.rsa.pub", "wolfi-signing.rsa.pub"},
	}, {
		name: "refuses to overwrite an existing key",
		keys: []types.RuntimeKeyringEntry{inlineKey("wolfi-signing.rsa.pub", keyPEM)},
		existing: map[string][]byte{
			filepath.Join(apkKeysDir, "wolfi-signing.rsa.pub"): []byte("existing-distro-key"),
		},
		wantErr: true,
	}, {
		name:    "same name, different content collides",
		keys:    []types.RuntimeKeyringEntry{inlineKey("dup.rsa.pub", keyPEM), inlineKey("dup.rsa.pub", rsaPublicKeyPEM(t))},
		wantErr: true,
	}, {
		name:    "rejects a non-RSA key",
		keys:    []types.RuntimeKeyringEntry{inlineKey("ec.rsa.pub", ecPublicKeyPEM(t))},
		wantErr: true,
	}, {
		name:    "rejects malformed PEM",
		keys:    []types.RuntimeKeyringEntry{inlineKey("bad.rsa.pub", "not a pem block")},
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
				ic: types.ImageConfiguration{Contents: types.ImageContents{RuntimeKeyring: tt.keys}},
				fs: fsys,
			}

			err := bc.installRuntimeKeyring(t.Context())
			if (err != nil) != tt.wantErr {
				t.Fatalf("installRuntimeKeyring() error = %v, wantErr %v", err, tt.wantErr)
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
				// installed runtime keys get the deterministic epoch.
				if _, isSetup := tt.existing[path]; !isSetup {
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

// A symlink at the key's path must never be silently written through — that
// would land the key outside /etc/apk/keys. The existence check uses Lstat so
// a symlink (even dangling, which Stat reports as not-exist) counts as a
// collision, on a real filesystem and on MemFS alike: either way the install
// fails and nothing is written through the link.
func TestInstallRuntimeKeyringRefusesSymlink(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1337")
	fsys := apkfs.NewMemFS()
	if err := fsys.MkdirAll(apkKeysDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := fsys.Symlink("/outside/target.rsa.pub", filepath.Join(apkKeysDir, "mirror.rsa.pub")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	bc := &Context{
		o: options.Options{SourceDateEpoch: time.Unix(1337, 0)},
		ic: types.ImageConfiguration{Contents: types.ImageContents{
			RuntimeKeyring: []types.RuntimeKeyringEntry{inlineKey("mirror.rsa.pub", rsaPublicKeyPEM(t))},
		}},
		fs: fsys,
	}

	err := bc.installRuntimeKeyring(t.Context())
	if err == nil {
		t.Fatal("installRuntimeKeyring() = nil, want an error for a symlinked key path")
	}
	if !strings.Contains(err.Error(), "collides with an existing /etc/apk/keys entry") {
		t.Fatalf("installRuntimeKeyring() = %v, want the symlink reported as a collision, not a write error", err)
	}
	if _, err := fsys.Stat("/outside/target.rsa.pub"); err == nil {
		t.Fatal("key content was written through the symlink outside /etc/apk/keys")
	}
}

// Runtime keys are content-bearing and written deterministically, so two runs
// with identical input produce byte-identical files.
func TestInstallRuntimeKeyringDeterministic(t *testing.T) {
	epoch := time.Unix(1337, 0)
	keyPEM := rsaPublicKeyPEM(t)
	keys := []types.RuntimeKeyringEntry{inlineKey("b.rsa.pub", keyPEM), inlineKey("a.rsa.pub", keyPEM)}

	run := func() map[string][]byte {
		t.Setenv("SOURCE_DATE_EPOCH", fmt.Sprintf("%d", epoch.Unix()))
		fsys := apkfs.NewMemFS()
		bc := &Context{
			o:  options.Options{SourceDateEpoch: epoch},
			ic: types.ImageConfiguration{Contents: types.ImageContents{RuntimeKeyring: keys}},
			fs: fsys,
		}
		if err := bc.installRuntimeKeyring(t.Context()); err != nil {
			t.Fatalf("installRuntimeKeyring: %v", err)
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

// Runtime keys live in a distinct field from the build keyring (contents.keyring),
// which is the only thing InitKeyring consumes — so they are never build-trusted.
func TestRuntimeKeyringDisjointFromBuildKeyring(t *testing.T) {
	ic := types.ImageConfiguration{Contents: types.ImageContents{
		RuntimeKeyring: []types.RuntimeKeyringEntry{inlineKey("mirror.rsa.pub", rsaPublicKeyPEM(t))},
	}}
	if len(ic.Contents.Keyring) != 0 {
		t.Errorf("runtime_keyring leaked into contents.keyring (the InitKeyring source): %v", ic.Contents.Keyring)
	}
}

type runtimeKeyDiscoveryRoundTripper func(*http.Request) (*http.Response, error)

func (rt runtimeKeyDiscoveryRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return rt(req)
}

type runtimeKeyDiscoveryBlockingRoundTripper struct {
	started chan struct{}
	once    sync.Once
}

func (rt *runtimeKeyDiscoveryBlockingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.once.Do(func() { close(rt.started) })
	<-req.Context().Done()
	return nil, req.Context().Err()
}

func TestBuildLayerIncludesConfiguredRuntimeKeyringOnly(t *testing.T) {
	t.Setenv("HTTP_AUTH", "")
	t.Setenv("SOURCE_DATE_EPOCH", "1337")

	buildKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	runtimeSigningKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	runtimeDER, err := x509.MarshalPKIXPublicKey(&runtimeSigningKey.PublicKey)
	require.NoError(t, err)
	runtimePEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: runtimeDER})
	runtimeKey := rsaPublicKeyPEM(t)
	keyFile := filepath.Join(t.TempDir(), "runtime-local.rsa.pub")
	require.NoError(t, os.WriteFile(keyFile, []byte(runtimeKey), 0o644))

	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &buildKey.PublicKey, KeyID: "build-only"}}})
	require.NoError(t, err)
	runtimeJWKS, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &runtimeSigningKey.PublicKey, KeyID: "runtime-only"}}})
	require.NoError(t, err)
	transport := runtimeKeyDiscoveryRoundTripper(func(req *http.Request) (*http.Response, error) {
		var body string
		switch req.URL.Host + req.URL.Path {
		case "build.example/build-only/apk-configuration":
			body = `{"jwks_uri":"https://build.example/build-only/jwks"}`
		case "build.example/build-only/jwks":
			body = string(jwks)
		case "runtime.example/runtime-only/apk-configuration":
			body = `{"jwks_uri":"https://keys.example/runtime-only/jwks"}`
		case "keys.example/runtime-only/jwks":
			body = string(runtimeJWKS)
		default:
			return nil, fmt.Errorf("unexpected request to %s", req.URL)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    req,
		}, nil
	})

	localRepo := filepath.Join(t.TempDir(), "local-repo")
	imageConfig := types.ImageConfiguration{Contents: types.ImageContents{
		BuildRepositories:       []string{"https://build.example/build-only"},
		RuntimeOnlyRepositories: []string{"https://runtime.example/runtime-only"},
		Repositories:            []string{localRepo},
		Keyring:                 []string{keyFile},
	}}
	bc, err := New(t.Context(), apkfs.NewMemFS(),
		WithImageConfiguration(imageConfig),
		WithJWKSAllowedOrigins("https://keys.example"),
		WithTransport(transport),
		WithCache(t.TempDir(), false, apk.NewCache(false)),
		WithPreResolvedPackages([]apk.PackageContents{}),
		WithArch(types.ParseArchitecture("amd64")),
	)
	require.NoError(t, err)

	_, layer, err := bc.BuildLayer(context.Background())
	require.NoError(t, err)
	contents, err := layer.Uncompressed()
	require.NoError(t, err)
	defer contents.Close()

	keyFiles := map[string][]byte{}
	tarReader := tar.NewReader(contents)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		if strings.HasPrefix(header.Name, "etc/apk/keys/") && header.Typeflag == tar.TypeReg {
			data, err := io.ReadAll(tarReader)
			require.NoError(t, err)
			keyFiles[header.Name] = data
		}
	}

	require.Equal(t, []byte(runtimeKey), keyFiles["etc/apk/keys/runtime-local.rsa.pub"])
	require.Equal(t, runtimePEM, keyFiles["etc/apk/keys/runtime-only.rsa.pub"])
	require.NotContains(t, keyFiles, "etc/apk/keys/build-only.rsa.pub")
}

func TestRuntimeOnlyKeyDiscoveryFailureWarnsAndContinuesBuild(t *testing.T) {
	t.Setenv("HTTP_AUTH", "")
	var logs bytes.Buffer
	ctx := clog.WithLogger(t.Context(), clog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
	var requests int
	transport := runtimeKeyDiscoveryRoundTripper(func(req *http.Request) (*http.Response, error) {
		requests++
		return &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Status:     "503 Service Unavailable",
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("unavailable")),
			Request:    req,
		}, nil
	})
	imageConfig := types.ImageConfiguration{Contents: types.ImageContents{
		BuildRepositories:       []string{filepath.Join(t.TempDir(), "build-repo")},
		RuntimeOnlyRepositories: []string{"https://runtime.example/unavailable"},
	}}
	bc, err := New(ctx, apkfs.NewMemFS(),
		WithImageConfiguration(imageConfig),
		WithTransport(transport),
		WithPreResolvedPackages([]apk.PackageContents{}),
		WithArch(types.ParseArchitecture("amd64")),
	)
	require.NoError(t, err)

	_, _, err = bc.BuildLayer(ctx)
	require.NoError(t, err, "runtime-only discovery failure must not fail the build")
	require.Equal(t, 1, requests, "runtime-only discovery must not retry an unavailable endpoint")
	require.Contains(t, logs.String(), "key discovery for runtime-only repository")
	require.Contains(t, logs.String(), "runtime.example/unavailable")
	require.Contains(t, logs.String(), "503 Service Unavailable")
	require.Contains(t, logs.String(), "continuing build")
}

func TestRuntimeOnlyKeyDiscoveryTimesOutQuickly(t *testing.T) {
	t.Setenv("HTTP_AUTH", "")
	var logs bytes.Buffer
	ctx := clog.WithLogger(t.Context(), clog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
	transport := &runtimeKeyDiscoveryBlockingRoundTripper{started: make(chan struct{})}
	imageConfig := types.ImageConfiguration{Contents: types.ImageContents{
		BuildRepositories:       []string{filepath.Join(t.TempDir(), "build-repo")},
		RuntimeOnlyRepositories: []string{"https://runtime.example/unreachable"},
	}}
	bc, err := New(ctx, apkfs.NewMemFS(),
		WithImageConfiguration(imageConfig),
		WithTransport(transport),
		WithPreResolvedPackages([]apk.PackageContents{}),
		WithArch(types.ParseArchitecture("amd64")),
	)
	require.NoError(t, err)

	buildCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	start := time.Now()
	_, _, err = bc.BuildLayer(buildCtx)
	elapsed := time.Since(start)
	require.NoError(t, err, "an unreachable runtime-only repository must not fail the build")
	require.Less(t, elapsed, 7*time.Second, "runtime-only discovery should use its short client timeout")
	select {
	case <-transport.started:
	default:
		t.Fatal("runtime-only repository was not contacted")
	}
	require.Contains(t, logs.String(), "continuing build")
}

func TestParsePublicKey(t *testing.T) {
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
			got, err := parsePublicKey(tt.content)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parsePublicKey() error = %v, wantErr %v", err, tt.wantErr)
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
func TestParsePublicKeyDropsTrailingBytes(t *testing.T) {
	keyPEM := rsaPublicKeyPEM(t)
	got, err := parsePublicKey(keyPEM + "\ntrailing junk that is not pem\n")
	if err != nil {
		t.Fatalf("parsePublicKey: %v", err)
	}
	if strings.Contains(string(got), "trailing junk") {
		t.Errorf("re-encoded key retained trailing bytes:\n%s", got)
	}
}

// The DoD invariant: inline runtime keys are content-addressed. The serialized
// configuration carries the key content (so identity is reproducible) but never
// a host path, temp dir, or file:// URI.
func TestRuntimeKeyringSerializationCarriesContentNotPath(t *testing.T) {
	keyPEM := rsaPublicKeyPEM(t)
	ic := types.ImageConfiguration{Contents: types.ImageContents{
		RuntimeKeyring: []types.RuntimeKeyringEntry{inlineKey("mirror.rsa.pub", keyPEM)},
	}}

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
	if !strings.Contains(s, "runtime_keyring") || !strings.Contains(s, "BEGIN PUBLIC KEY") {
		t.Errorf("serialized config missing runtime keyring content:\n%s", s)
	}
	for _, banned := range []string{"file://", "/tmp/", "/etc/apk/keys", string(filepath.Separator) + "var" + string(filepath.Separator)} {
		if strings.Contains(s, banned) {
			t.Errorf("serialized config leaked a path substring %q:\n%s", banned, s)
		}
	}
}
