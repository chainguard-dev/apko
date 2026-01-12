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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/pavlo-v-chernykh/keystore-go/v4"
	"go.opentelemetry.io/otel"
)

const (
	// Directory for individual certificate files (used by update-ca-certificates).
	caCertsDir = "usr/local/share/ca-certificates"
)

var (
	// Common paths for CA bundles.
	caBundlePaths = []string{
		"etc/ssl/certs/ca-certificates.crt",                        // Alpine default.
		"var/lib/ecs/deps/execute-command/certs/tls-ca-bundle.pem", // AWS ECS-specific.
	}

	// Common paths for Java truststores.
	javaTruststorePaths = []string{
		"etc/ssl/certs/java/cacerts", // Common location for Java cacerts.
	}

	// Default password for Java cacerts truststore.
	javaTruststorePassword = []byte("changeit")
)

// parsedCertificate represents a parsed certificate with its metadata.
type parsedCertificate struct {
	structured  *x509.Certificate
	pem         []byte
	fingerprint string
}

// loadedTruststore represents a Java truststore loaded into memory.
type loadedTruststore struct {
	path string
	mode fs.FileMode
	ks   keystore.KeyStore
}

// installCertificates installs inline certificates into the build context.
func (bc *Context) installCertificates(ctx context.Context) error {
	_, span := otel.Tracer("apko").Start(ctx, "installCertificates")
	defer span.End()

	if bc.ic.Certificates == nil || len(bc.ic.Certificates.Additional) == 0 {
		// No configuration, nothing to do.
		return nil
	}

	builtTime, err := bc.GetBuildDateEpoch()
	if err != nil {
		return fmt.Errorf("failed to get build date epoch: %w", err)
	}

	// Create the ca-certificates directory if it doesn't exist
	if err := bc.fs.MkdirAll(caCertsDir, 0o755); err != nil {
		return fmt.Errorf("failed to create ca-certificates directory: %w", err)
	}

	// Open handles for all existing CA bundles to append to.
	existingBundles := make([]io.WriteSeeker, 0, len(caBundlePaths))
	for _, caBundlePath := range caBundlePaths {
		file, err := bc.fs.OpenFile(caBundlePath, os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				// If the bundle doesn't exist, nothing to do, we just ignore that.
				continue
			}
			return fmt.Errorf("failed to open CA bundle for appending: %w", err)
		}
		defer file.Close()

		existingBundles = append(existingBundles, file)
	}

	// Load all existing Java truststores to append to. This will be empty for
	// images that have no Java truststore installed, so the processes below
	// will be no-ops in that case.
	existingTruststores, err := bc.loadJavaTruststores()
	if err != nil {
		return fmt.Errorf("failed to load Java truststores: %w", err)
	}

	for _, additional := range bc.ic.Certificates.Additional {
		cert, err := parseCertificates(additional.Content)
		if err != nil {
			return fmt.Errorf("failed to parse certificate %s: %w", additional.Name, err)
		}

		// Write individual certificate file for update-ca-certificates to pick up.
		// Name is validated not to do any path shenanigans on configuration validation.
		// The fingerprint is controlled to be a hash and so also doesn't allow shenanigans.
		certPath := filepath.Join(caCertsDir, fmt.Sprintf("%s-%s.crt", additional.Name, cert.fingerprint))
		if err := bc.fs.WriteFile(certPath, cert.pem, 0o644); err != nil {
			return fmt.Errorf("failed to write certificate file %s: %w", certPath, err)
		}
		if err := bc.fs.Chtimes(certPath, builtTime, builtTime); err != nil {
			return fmt.Errorf("failed to change times on certificate file %s: %w", certPath, err)
		}

		// Append to all existing CA bundles.
		for _, bundle := range existingBundles {
			if _, err := bundle.Write(cert.pem); err != nil {
				return fmt.Errorf("failed to append certificate to bundle: %w", err)
			}
			// Put newlines in-between certificates to mimic update-ca-certificates behavior.
			if _, err := bundle.Write([]byte("\n")); err != nil {
				return fmt.Errorf("failed to append newline to bundle: %w", err)
			}
		}

		// Append to all existing Java truststores.
		for _, ts := range existingTruststores {
			entry := keystore.TrustedCertificateEntry{
				CreationTime: builtTime,
				Certificate: keystore.Certificate{
					Type:    "X.509",
					Content: cert.structured.Raw,
				},
			}
			alias := fmt.Sprintf("%s-%s", additional.Name, cert.fingerprint)
			if err := ts.ks.SetTrustedCertificateEntry(alias, entry); err != nil {
				return fmt.Errorf("failed to add certificate to Java truststore: %w", err)
			}
		}
	}

	for _, caBundlePath := range caBundlePaths {
		if err := bc.fs.Chtimes(caBundlePath, builtTime, builtTime); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("failed to change times on CA bundle %s: %w", caBundlePath, err)
		}
	}

	// Write all modified Java truststores back to disk.
	for _, ts := range existingTruststores {
		var buf bytes.Buffer
		if err := ts.ks.Store(&buf, javaTruststorePassword); err != nil {
			return fmt.Errorf("failed to encode Java truststore %s: %w", ts.path, err)
		}
		if err := bc.fs.WriteFile(ts.path, buf.Bytes(), ts.mode); err != nil {
			return fmt.Errorf("failed to write Java truststore %s: %w", ts.path, err)
		}
		if err := bc.fs.Chtimes(ts.path, builtTime, builtTime); err != nil {
			return fmt.Errorf("failed to change times on Java truststore %s: %w", ts.path, err)
		}
	}

	return nil
}

// loadJavaTruststores loads all existing Java truststores from the configured paths.
// It is ok if no truststores exist; in that case, an empty slice is returned.
func (bc *Context) loadJavaTruststores() ([]loadedTruststore, error) {
	truststores := make([]loadedTruststore, 0, len(javaTruststorePaths))
	for _, truststorePath := range javaTruststorePaths {
		stat, err := bc.fs.Stat(truststorePath)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				// If the truststore doesn't exist, nothing to do, we just ignore that.
				continue
			}
			return nil, fmt.Errorf("failed to stat Java truststore %s: %w", truststorePath, err)
		}

		file, err := bc.fs.Open(truststorePath)
		if err != nil {
			return nil, fmt.Errorf("failed to open Java truststore %s: %w", truststorePath, err)
		}
		defer file.Close()

		// WithOrderedAliases to ensure deterministic output.
		ks := keystore.New(keystore.WithOrderedAliases())
		if err := ks.Load(file, javaTruststorePassword); err != nil {
			return nil, fmt.Errorf("failed to load Java truststore %s: %w", truststorePath, err)
		}

		truststores = append(truststores, loadedTruststore{
			path: truststorePath,
			mode: stat.Mode(),
			ks:   ks,
		})
	}
	return truststores, nil
}

// parseCertificates parses a string as a PEM-encoded certificate and returns
// a parsedCertificate struct.
func parseCertificates(pemData string) (*parsedCertificate, error) {
	if pemData == "" {
		return nil, fmt.Errorf("no certificate data provided")
	}

	var cert *parsedCertificate
	rest := []byte(pemData)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		} else if cert != nil {
			// More than one certificate found.
			return nil, fmt.Errorf("multiple certificates found; only one is allowed")
		}

		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("expected CERTIFICATE block, got %s", block.Type)
		}

		// Parse the certificate to validate it
		parsed, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}

		// Generate fingerprint (SHA256 hash of DER-encoded certificate).
		hash := sha256.Sum256(block.Bytes)
		fingerprint := hex.EncodeToString(hash[:])

		// Re-encode to PEM. This drops any additional text from the original block.
		var pemBuf bytes.Buffer
		if err := pem.Encode(&pemBuf, block); err != nil {
			return nil, fmt.Errorf("failed to re-encode certificate to PEM: %w", err)
		}

		cert = &parsedCertificate{
			structured:  parsed,
			pem:         pemBuf.Bytes(),
			fingerprint: fingerprint,
		}
	}

	if cert == nil {
		return nil, fmt.Errorf("no certificates found in PEM data")
	}
	return cert, nil
}
