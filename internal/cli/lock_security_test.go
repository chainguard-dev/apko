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
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

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
