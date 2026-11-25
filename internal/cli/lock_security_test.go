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

package cli

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/build/types"
)

type lockTestRoundTripper func(*http.Request) (*http.Response, error)

func (rt lockTestRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return rt(req)
}

func TestDiscoverKeysForLockUsesJWKSAllowedOrigins(t *testing.T) {
	t.Setenv("HTTP_AUTH", "")
	const repo = "https://repo.example/wolfi"
	var mirrorCalled bool
	transport := lockTestRoundTripper(func(req *http.Request) (*http.Response, error) {
		var status int
		var body string
		switch {
		case req.URL.Host == "repo.example" && req.URL.Path == "/wolfi/apk-configuration":
			status = http.StatusOK
			body = `{"jwks_uri":"https://keys.example/jwks"}`
		case req.URL.Host == "keys.example" && req.URL.Path == "/jwks":
			mirrorCalled = true
			status = http.StatusOK
			body = `{"keys":[]}`
		default:
			return nil, fmt.Errorf("unexpected request to %s", req.URL)
		}
		return &http.Response{
			StatusCode: status,
			Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    req,
		}, nil
	})
	client := &http.Client{Transport: transport}
	imageConfig := &types.ImageConfiguration{}
	imageConfig.Contents.BuildRepositories = []string{repo}

	keys, err := discoverKeysForLock(t.Context(), imageConfig, nil, client, "https://keys.example")
	require.NoError(t, err)
	require.Empty(t, keys)
	require.True(t, mirrorCalled, "lock generation must pass its configured JWKS origins to key discovery")
}

func TestJWKSAllowedOriginFlagsAreAvailableOnDiscoveryCommands(t *testing.T) {
	commands := []struct {
		name string
		cmd  *cobra.Command
	}{
		{name: "build", cmd: buildCmd()},
		{name: "publish", cmd: publish()},
		{name: "lock", cmd: lock()},
		{name: "resolve", cmd: resolve()},
		{name: "install-keys", cmd: installKeys()},
		{name: "build-minirootfs", cmd: buildMinirootFS()},
		{name: "build-cpio", cmd: buildCPIO()},
		{name: "dot", cmd: dotcmd()},
		{name: "show-packages", cmd: showPackages()},
	}

	for _, tt := range commands {
		t.Run(tt.name, func(t *testing.T) {
			require.NotNil(t, tt.cmd.Flags().Lookup("jwks-allowed-origin"))
		})
	}
}

func TestJWKSAllowedOriginCLIFlagSupportsMultipleOriginsInLockDiscovery(t *testing.T) {
	t.Setenv("HTTP_AUTH", "")
	var origins []string
	cmd := &cobra.Command{}
	addJWKSAllowedOriginFlag(cmd, &origins)
	require.NoError(t, cmd.Flags().Set("jwks-allowed-origin", "https://keys-a.example"))
	require.NoError(t, cmd.Flags().Set("jwks-allowed-origin", "https://keys-b.example"))
	require.Equal(t, []string{"https://keys-a.example", "https://keys-b.example"}, origins)

	options, _, err := build.NewOptions(build.WithJWKSAllowedOrigins(origins...))
	require.NoError(t, err)

	const repoA = "https://repo.example/a"
	const repoB = "https://repo.example/b"
	var keysA, keysB bool
	transport := lockTestRoundTripper(func(req *http.Request) (*http.Response, error) {
		var body string
		switch req.URL.Host + req.URL.Path {
		case "repo.example/a/apk-configuration":
			body = `{"jwks_uri":"https://keys-a.example/jwks"}`
		case "repo.example/b/apk-configuration":
			body = `{"jwks_uri":"https://keys-b.example/jwks"}`
		case "keys-a.example/jwks":
			keysA = true
			body = `{"keys":[]}`
		case "keys-b.example/jwks":
			keysB = true
			body = `{"keys":[]}`
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
	imageConfig := &types.ImageConfiguration{}
	imageConfig.Contents.BuildRepositories = []string{repoA, repoB}

	_, err = discoverKeysForLock(t.Context(), imageConfig, nil, &http.Client{Transport: transport}, options.JWKSAllowedOrigins...)
	require.NoError(t, err)
	require.True(t, keysA, "the first explicitly allowed JWKS origin should be reached")
	require.True(t, keysB, "the second explicitly allowed JWKS origin should be reached")
}

func TestDiscoverKeysForLockRejectsCrossOriginWithoutCLIAllowlist(t *testing.T) {
	t.Setenv("HTTP_AUTH", "")
	const repo = "https://repo.example/wolfi"
	var jwksRequested bool
	transport := lockTestRoundTripper(func(req *http.Request) (*http.Response, error) {
		var body string
		switch req.URL.Host + req.URL.Path {
		case "repo.example/wolfi/apk-configuration":
			body = `{"jwks_uri":"https://untrusted.example/jwks"}`
		case "untrusted.example/jwks":
			jwksRequested = true
			body = `{"keys":[]}`
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
	imageConfig := &types.ImageConfiguration{}
	imageConfig.Contents.BuildRepositories = []string{repo}

	_, err := discoverKeysForLock(t.Context(), imageConfig, nil, &http.Client{Transport: transport})
	require.NoError(t, err)
	require.False(t, jwksRequested, "a cross-origin JWKS URL must remain blocked without an explicit CLI allowlist")
}

func TestDiscoverKeysForLockEscapesKeyIDInURL(t *testing.T) {
	t.Setenv("HTTP_AUTH", "")
	const repo = "https://repo.example/wolfi"
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwksBody, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &rsaKey.PublicKey, KeyID: "rsa-test"},
		{Key: &rsaKey.PublicKey, KeyID: "a?b#c%2f"},
	}})
	require.NoError(t, err)

	transport := lockTestRoundTripper(func(req *http.Request) (*http.Response, error) {
		var body string
		switch req.URL.Host + req.URL.Path {
		case "repo.example/wolfi/apk-configuration":
			body = `{"jwks_uri":"https://repo.example/jwks"}`
		case "repo.example/jwks":
			body = string(jwksBody)
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
	imageConfig := &types.ImageConfiguration{}
	imageConfig.Contents.BuildRepositories = []string{repo}

	keys, err := discoverKeysForLock(t.Context(), imageConfig, nil, &http.Client{Transport: transport})
	require.NoError(t, err)
	require.Len(t, keys, 2)
	urls := make(map[string]string, len(keys))
	requestedPaths := make([]string, 0, len(keys))
	for _, key := range keys {
		urls[key.URL] = key.Name
		parsed, err := url.Parse(key.URL)
		require.NoError(t, err)
		requestedPaths = append(requestedPaths, parsed.Path)
	}
	require.Equal(t, map[string]string{
		repo + "/rsa-test.rsa.pub":       "repo.example/wolfi/rsa-test.rsa.pub",
		repo + "/a%3Fb%23c%252f.rsa.pub": "repo.example/wolfi/a%3Fb%23c%252f.rsa.pub",
	}, urls, "ordinary key IDs must be unchanged and other key IDs must be escaped as one path segment")
	require.ElementsMatch(t, []string{"/wolfi/rsa-test.rsa.pub", "/wolfi/a?b#c%2f.rsa.pub"}, requestedPaths,
		"a consumer fetching the key URL must request the literal key ID as one path segment")
}
