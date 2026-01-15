// Copyright 2023 Chainguard, Inc.
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

package keyring

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"

	"go.opentelemetry.io/otel"
	"go.step.sm/crypto/jose"
)

func fetchJWKSURLFromDiscovery(ctx context.Context, fetcher Fetcher, discoveryURL string) (string, error) {
	ctx, span := otel.Tracer("go-apk").Start(ctx, "jwksURLFromDiscovery")
	defer span.End()

	discoveryResponse, err := fetcher(ctx, discoveryURL, true)
	if err != nil {
		return "", fmt.Errorf("failed to perform key discovery: %w", err)
	}
	defer discoveryResponse.Body.Close()

	switch discoveryResponse.StatusCode {
	case http.StatusNotFound:
		// This doesn't implement Chainguard-style key discovery.
		return "", nil

	case http.StatusOK:
		// proceed!
		break

	default:
		return "", fmt.Errorf("chainguard key discovery was unsuccessful for repo %s: %v", discoveryURL, discoveryResponse.Status)
	}

	// Parse our the JWKS URI
	var discovery struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(discoveryResponse.Body).Decode(&discovery); err != nil {
		return "", fmt.Errorf("failed to unmarshal discovery payload: %w", err)
	}

	return discovery.JWKSURI, nil
}

func fetchKeysFromJWKS(ctx context.Context, fetcher Fetcher, jwksURL jwksURLInfo) ([]Key, error) {
	jwks := jose.JSONWebKeySet{}
	{
		jwksResponse, err := fetcher(ctx, jwksURL.url, true)
		if err != nil {
			return nil, err
		}
		defer jwksResponse.Body.Close()

		if jwksResponse.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("failed to fetch JWKS: %v", jwksResponse.Status)
		}

		if err := json.NewDecoder(jwksResponse.Body).Decode(&jwks); err != nil {
			return nil, fmt.Errorf("failed to unmarshal JWKS: %w", err)
		}
	}

	keys := make([]Key, 0, len(jwks.Keys))
	for _, key := range jwks.Keys {
		if key.KeyID == "" {
			return nil, fmt.Errorf(`key missing "kid"`)
		}
		keyName := key.KeyID + ".rsa.pub"

		b, err := x509.MarshalPKIXPublicKey(key.Key.(*rsa.PublicKey))
		if err != nil {
			return nil, err
		} else if len(b) == 0 {
			return nil, fmt.Errorf("empty public key")
		}

		var buf bytes.Buffer
		if err := pem.Encode(&buf, &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: b,
		}); err != nil {
			return nil, fmt.Errorf("failed to pem encode key %s: %w", keyName, err)
		}

		keys = append(keys, Key{
			ID:    keyName,
			Bytes: buf.Bytes(),
			URL:   strings.TrimSuffix(jwksURL.discoveryURL, "/apk-configuration") + "/" + key.KeyID + ".rsa.pub",
		})
	}

	return keys, nil
}
