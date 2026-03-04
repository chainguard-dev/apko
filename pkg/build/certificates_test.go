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
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"chainguard.dev/apko/pkg/apk/apk"
	apkfs "chainguard.dev/apko/pkg/apk/fs"
	apktypes "chainguard.dev/apko/pkg/apk/types"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/options"

	"github.com/google/go-cmp/cmp"
	"github.com/pavlo-v-chernykh/keystore-go/v4"
)

const (
	// From https://letsencrypt.org/certs/staging/letsencrypt-stg-root-x1.pem
	testCertPEM = `-----BEGIN CERTIFICATE-----
MIIFmDCCA4CgAwIBAgIQU9C87nMpOIFKYpfvOHFHFDANBgkqhkiG9w0BAQsFADBm
MQswCQYDVQQGEwJVUzEzMDEGA1UEChMqKFNUQUdJTkcpIEludGVybmV0IFNlY3Vy
aXR5IFJlc2VhcmNoIEdyb3VwMSIwIAYDVQQDExkoU1RBR0lORykgUHJldGVuZCBQ
ZWFyIFgxMB4XDTE1MDYwNDExMDQzOFoXDTM1MDYwNDExMDQzOFowZjELMAkGA1UE
BhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1cml0eSBSZXNl
YXJjaCBHcm91cDEiMCAGA1UEAxMZKFNUQUdJTkcpIFByZXRlbmQgUGVhciBYMTCC
AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALbagEdDTa1QgGBWSYkyMhsc
ZXENOBaVRTMX1hceJENgsL0Ma49D3MilI4KS38mtkmdF6cPWnL++fgehT0FbRHZg
jOEr8UAN4jH6omjrbTD++VZneTsMVaGamQmDdFl5g1gYaigkkmx8OiCO68a4QXg4
wSyn6iDipKP8utsE+x1E28SA75HOYqpdrk4HGxuULvlr03wZGTIf/oRt2/c+dYmD
oaJhge+GOrLAEQByO7+8+vzOwpNAPEx6LW+crEEZ7eBXih6VP19sTGy3yfqK5tPt
TdXXCOQMKAp+gCj/VByhmIr+0iNDC540gtvV303WpcbwnkkLYC0Ft2cYUyHtkstO
fRcRO+K2cZozoSwVPyB8/J9RpcRK3jgnX9lujfwA/pAbP0J2UPQFxmWFRQnFjaq6
rkqbNEBgLy+kFL1NEsRbvFbKrRi5bYy2lNms2NJPZvdNQbT/2dBZKmJqxHkxCuOQ
FjhJQNeO+Njm1Z1iATS/3rts2yZlqXKsxQUzN6vNbD8KnXRMEeOXUYvbV4lqfCf8
mS14WEbSiMy87GB5S9ucSV1XUrlTG5UGcMSZOBcEUpisRPEmQWUOTWIoDQ5FOia/
GI+Ki523r2ruEmbmG37EBSBXdxIdndqrjy+QVAmCebyDx9eVEGOIpn26bW5LKeru
mJxa/CFBaKi4bRvmdJRLAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMB
Af8EBTADAQH/MB0GA1UdDgQWBBS182Xy/rAKkh/7PH3zRKCsYyXDFDANBgkqhkiG
9w0BAQsFAAOCAgEAncDZNytDbrrVe68UT6py1lfF2h6Tm2p8ro42i87WWyP2LK8Y
nLHC0hvNfWeWmjZQYBQfGC5c7aQRezak+tHLdmrNKHkn5kn+9E9LCjCaEsyIIn2j
qdHlAkepu/C3KnNtVx5tW07e5bvIjJScwkCDbP3akWQixPpRFAsnP+ULx7k0aO1x
qAeaAhQ2rgo1F58hcflgqKTXnpPM02intVfiVVkX5GXpJjK5EoQtLceyGOrkxlM/
sTPq4UrnypmsqSagWV3HcUlYtDinc+nukFk6eR4XkzXBbwKajl0YjztfrCIHOn5Q
CJL6TERVDbM/aAPly8kJ1sWGLuvvWYzMYgLzDul//rUF10gEMWaXVZV51KpS9DY/
5CunuvCXmEQJHo7kGcViT7sETn6Jz9KOhvYcXkJ7po6d93A/jy4GKPIPnsKKNEmR
xUuXY4xRdh45tMJnLTUDdC9FIU0flTeO9/vNpVA8OPU1i14vCz+MU8KX1bV3GXm/
fxlB7VBBjX9v5oUep0o/j68R/iDlCOM4VVfRa8gX6T2FU7fNdatvGro7uQzIvWof
gN9WUwCbEMBy/YhBSrXycKA8crgGg3x1mIsopn88JKwmMBa68oS7EHM9w7C4y71M
7DiA+/9Qdp9RBWJpTS9i/mDnJg1xvo8Xz49mrrgfmcAXTCJqXi24NatI3Oc=
-----END CERTIFICATE-----
`
	testCertPEMFingerprint = "e70570a989f8565aabdf7cae27abd1621872d6a3f811e3fef27e3dba02912198"

	// From https://letsencrypt.org/certs/staging/letsencrypt-stg-root-x2.pem
	testCertPEM2 = `-----BEGIN CERTIFICATE-----
MIICTjCCAdSgAwIBAgIRAIPgc3k5LlLVLtUUvs4K/QcwCgYIKoZIzj0EAwMwaDEL
MAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1cml0
eSBSZXNlYXJjaCBHcm91cDEkMCIGA1UEAxMbKFNUQUdJTkcpIEJvZ3VzIEJyb2Nj
b2xpIFgyMB4XDTIwMDkwNDAwMDAwMFoXDTQwMDkxNzE2MDAwMFowaDELMAkGA1UE
BhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1cml0eSBSZXNl
YXJjaCBHcm91cDEkMCIGA1UEAxMbKFNUQUdJTkcpIEJvZ3VzIEJyb2Njb2xpIFgy
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEOvS+w1kCzAxYOJbA06Aw0HFP2tLBLKPo
FQqR9AMskl1nC2975eQqycR+ACvYelA8rfwFXObMHYXJ23XLB+dAjPJVOJ2OcsjT
VqO4dcDWu+rQ2VILdnJRYypnV1MMThVxo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYD
VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU3tGjWWQOwZo2o0busBB2766XlWYwCgYI
KoZIzj0EAwMDaAAwZQIwRcp4ZKBsq9XkUuN8wfX+GEbY1N5nmCRc8e80kUkuAefo
uc2j3cICeXo1cOybQ1iWAjEA3Ooawl8eQyR4wrjCofUE8h44p0j7Yl/kBlJZT8+9
vbtH7QiVzeKCOTQPINyRql6P
-----END CERTIFICATE-----
`
	testCertPEM2Fingerprint = "9b2a339fe6a3e85585c4cd75536cb8c1cf7cd603b9a64bec2521858ae48da85d"

	// Self-signed test certificate 3 (EC P-256, CN=Test CA Certificate 3).
	testCertPEM3 = `-----BEGIN CERTIFICATE-----
MIIBwjCCAWegAwIBAgIUBKZDifzRAz30jwlcoQLIOxkBPLMwCgYIKoZIzj0EAwIw
NTEeMBwGA1UEAwwVVGVzdCBDQSBDZXJ0aWZpY2F0ZSAzMRMwEQYDVQQKDApUZXN0
IE9yZyAzMCAXDTI2MDIyNzIwMzk1OVoYDzIxMjYwMjAzMjAzOTU5WjA1MR4wHAYD
VQQDDBVUZXN0IENBIENlcnRpZmljYXRlIDMxEzARBgNVBAoMClRlc3QgT3JnIDMw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARx/10O/q2rOnQtpBXHjARAUryfNWjD
UXeshzFk44hrv45loTsGQcyb5vAL6h3FSdBN91njUch4eF1NEYLKoR3Qo1MwUTAd
BgNVHQ4EFgQUhLbWEa0IUIixKPBVvuKxhK6UMnMwHwYDVR0jBBgwFoAUhLbWEa0I
UIixKPBVvuKxhK6UMnMwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNJADBG
AiEAqgTlOPOiNJLPJhMjRl9Zpaq6TTGfh+awe7N3fcEdHVICIQDfgVRRkuv1KTWk
44YBh2/IaTSFwFo8cd39Fnv7CYi/2g==
-----END CERTIFICATE-----
`
	testCertPEM3Fingerprint = "347537af7a09d403f19f58f83c3568912af24b7c12e745f1d5557079708c91ad"

	// Self-signed test certificate 4 (EC P-256, CN=Test CA Certificate 4).
	testCertPEM4 = `-----BEGIN CERTIFICATE-----
MIIBwTCCAWegAwIBAgIUPrm4YvABD98JhdU93qPsAgryo0UwCgYIKoZIzj0EAwIw
NTEeMBwGA1UEAwwVVGVzdCBDQSBDZXJ0aWZpY2F0ZSA0MRMwEQYDVQQKDApUZXN0
IE9yZyA0MCAXDTI2MDIyNzIwNDAwMFoYDzIxMjYwMjAzMjA0MDAwWjA1MR4wHAYD
VQQDDBVUZXN0IENBIENlcnRpZmljYXRlIDQxEzARBgNVBAoMClRlc3QgT3JnIDQw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQbR9hBg7/IeSBYJzUvBUxnnaNmoOJj
ESG5CiOa2980CC5aixcLof5kk/9K16B+OLIGSUE+Ya98N0vNP8KmDmvBo1MwUTAd
BgNVHQ4EFgQU6ZlpZtkvodhxZX1aRsM44dY0SJ8wHwYDVR0jBBgwFoAU6ZlpZtkv
odhxZX1aRsM44dY0SJ8wDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBF
AiARCNSY4WZ7Tl1oAmWghJz0Sxzi57JY4pdrvzyzYQNrhgIhAPMAzTOf33fVRhaX
wB7TKj2HAGTDpoliTH80SMWJN3jK
-----END CERTIFICATE-----
`
	testCertPEM4Fingerprint = "12ae34999aa64dcd1a6947e838a53aababfcfaca45abca8dc0cbb8dcb7bd063c"
)

func TestParseCertificates(t *testing.T) {
	tests := []struct {
		name            string
		pemData         string
		wantFingerprint string
		wantPEM         []byte
		wantErr         bool
	}{{
		name:            "single valid certificate",
		pemData:         testCertPEM,
		wantFingerprint: testCertPEMFingerprint,
		wantPEM:         []byte(testCertPEM),
		wantErr:         false,
	}, {
		name:            "single valid certificate with extra text",
		pemData:         "extra text\n" + testCertPEM,
		wantFingerprint: testCertPEMFingerprint,
		wantPEM:         []byte(testCertPEM), // The extra text is stripped.
		wantErr:         false,
	}, {
		name:    "multiple certificates",
		pemData: testCertPEM + "\n" + testCertPEM2,
		wantErr: true,
	}, {
		name:    "empty string",
		pemData: "",
		wantErr: true,
	}, {
		name:    "invalid PEM",
		pemData: "not a certificate",
		wantErr: true,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := parseCertificates(tt.pemData)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error but got none")
				}
				return
			}

			if diff := cmp.Diff(tt.wantFingerprint, cert.fingerprint); diff != "" {
				t.Errorf("fingerprint mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.wantPEM, cert.pem); diff != "" {
				t.Errorf("PEM data mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestInstallCertificates(t *testing.T) {
	epoch := time.Unix(1337, 0)
	t.Setenv("SOURCE_DATE_EPOCH", fmt.Sprintf("%d", epoch.Unix()))

	createTruststore := func(certs map[string]string) []byte {
		ks := keystore.New(keystore.WithOrderedAliases())
		for name, content := range certs {
			cert, err := parseCertificates(content)
			if err != nil {
				t.Fatalf("failed to parse certificate: %v", err)
			}
			entry := keystore.TrustedCertificateEntry{
				CreationTime: epoch,
				Certificate: keystore.Certificate{
					Type:    "X.509",
					Content: cert.structured.Raw,
				},
			}
			if err := ks.SetTrustedCertificateEntry(name, entry); err != nil {
				t.Fatalf("failed to add certificate to truststore: %v", err)
			}
		}
		var buf bytes.Buffer
		if err := ks.Store(&buf, javaTruststorePassword); err != nil {
			t.Fatalf("failed to store truststore: %v", err)
		}
		return buf.Bytes()
	}

	type pkgEntry struct {
		pkg   apktypes.Package
		files []tar.Header
	}

	tests := []struct {
		name          string
		cfg           *types.ImageCertificates // inline certs
		pkgs          []pkgEntry               // package-provided certs
		certData      map[string][]byte        // cert file contents for packages
		existingFiles map[string][]byte
		wantFiles     map[string][]byte
		wantErr       bool
	}{{
		// Inline certificate tests.
		name: "nil certificates config",
		cfg:  nil,
	}, {
		name: "valid single certificate without existing bundle",
		cfg: &types.ImageCertificates{
			Additional: []types.AdditionalCertificateEntry{
				{Name: "test-cert", Content: testCertPEM},
			},
		},
		existingFiles: map[string][]byte{},
		wantFiles: map[string][]byte{
			filepath.Join(caCertsDir, fmt.Sprintf("test-cert-%s.crt", testCertPEMFingerprint)): []byte(testCertPEM),
		},
	}, {
		name: "multiple certificate entries only one existing bundle",
		cfg: &types.ImageCertificates{
			Additional: []types.AdditionalCertificateEntry{
				{Name: "test-cert-1", Content: testCertPEM},
				{Name: "test-cert-2", Content: testCertPEM2},
			},
		},
		existingFiles: map[string][]byte{
			caBundlePaths[0]: []byte("# Existing CA Bundle\n"),
		},
		wantFiles: map[string][]byte{
			caBundlePaths[0]: []byte("# Existing CA Bundle\n" + testCertPEM + "\n" + testCertPEM2 + "\n"),
			filepath.Join(caCertsDir, fmt.Sprintf("test-cert-1-%s.crt", testCertPEMFingerprint)):  []byte(testCertPEM),
			filepath.Join(caCertsDir, fmt.Sprintf("test-cert-2-%s.crt", testCertPEM2Fingerprint)): []byte(testCertPEM2),
		},
	}, {
		name: "multiple certificate entries with multiple existing bundles",
		cfg: &types.ImageCertificates{
			Additional: []types.AdditionalCertificateEntry{
				{Name: "test-cert-1", Content: testCertPEM},
				{Name: "test-cert-2", Content: testCertPEM2},
			},
		},
		existingFiles: map[string][]byte{
			caBundlePaths[0]: []byte("# Existing CA Bundle\n"),
			caBundlePaths[1]: []byte("# Another CA Bundle\n"),
		},
		wantFiles: map[string][]byte{
			caBundlePaths[0]: []byte("# Existing CA Bundle\n" + testCertPEM + "\n" + testCertPEM2 + "\n"),
			caBundlePaths[1]: []byte("# Another CA Bundle\n" + testCertPEM + "\n" + testCertPEM2 + "\n"),
			filepath.Join(caCertsDir, fmt.Sprintf("test-cert-1-%s.crt", testCertPEMFingerprint)):  []byte(testCertPEM),
			filepath.Join(caCertsDir, fmt.Sprintf("test-cert-2-%s.crt", testCertPEM2Fingerprint)): []byte(testCertPEM2),
		},
	}, {
		name: "multiple certificate entries with identical names",
		cfg: &types.ImageCertificates{
			Additional: []types.AdditionalCertificateEntry{
				{Name: "test-cert", Content: testCertPEM},
				{Name: "test-cert", Content: testCertPEM2},
			},
		},
		existingFiles: map[string][]byte{
			caBundlePaths[0]: []byte("# Existing CA Bundle\n"),
		},
		wantFiles: map[string][]byte{
			caBundlePaths[0]: []byte("# Existing CA Bundle\n" + testCertPEM + "\n" + testCertPEM2 + "\n"),
			filepath.Join(caCertsDir, fmt.Sprintf("test-cert-%s.crt", testCertPEMFingerprint)):  []byte(testCertPEM),
			filepath.Join(caCertsDir, fmt.Sprintf("test-cert-%s.crt", testCertPEM2Fingerprint)): []byte(testCertPEM2),
		},
	}, {
		name: "certificate with additional metadata",
		cfg: &types.ImageCertificates{
			Additional: []types.AdditionalCertificateEntry{
				{Name: "test-cert", Content: "additional text\n" + testCertPEM},
			},
		},
		existingFiles: map[string][]byte{
			caBundlePaths[0]: []byte("# Existing CA Bundle\n"),
		},
		wantFiles: map[string][]byte{
			caBundlePaths[0]: []byte("# Existing CA Bundle\n" + testCertPEM + "\n"),
			filepath.Join(caCertsDir, fmt.Sprintf("test-cert-%s.crt", testCertPEMFingerprint)): []byte(testCertPEM),
		},
	}, {
		name: "inline certificate with existing Java truststore",
		cfg: &types.ImageCertificates{
			Additional: []types.AdditionalCertificateEntry{
				{Name: "test-cert", Content: testCertPEM},
			},
		},
		existingFiles: map[string][]byte{
			caBundlePaths[0]: []byte("# Existing CA Bundle\n"),
			javaTruststorePaths[0]: createTruststore(map[string]string{
				"existing": testCertPEM2,
			}),
		},
		wantFiles: map[string][]byte{
			caBundlePaths[0]: []byte("# Existing CA Bundle\n" + testCertPEM + "\n"),
			filepath.Join(caCertsDir, fmt.Sprintf("test-cert-%s.crt", testCertPEMFingerprint)): []byte(testCertPEM),
			javaTruststorePaths[0]: createTruststore(map[string]string{
				"existing":                            testCertPEM2,
				"test-cert-" + testCertPEMFingerprint: testCertPEM,
			}),
		},
	}, {
		name: "multiple inline certificates with existing Java truststore",
		cfg: &types.ImageCertificates{
			Additional: []types.AdditionalCertificateEntry{
				{Name: "test-cert-1", Content: testCertPEM},
				{Name: "test-cert-2", Content: testCertPEM2},
			},
		},
		existingFiles: map[string][]byte{
			caBundlePaths[0]: []byte("# Existing CA Bundle\n"),
			javaTruststorePaths[0]: createTruststore(map[string]string{
				"existing": testCertPEM2,
			}),
		},
		wantFiles: map[string][]byte{
			caBundlePaths[0]: []byte("# Existing CA Bundle\n" + testCertPEM + "\n" + testCertPEM2 + "\n"),
			filepath.Join(caCertsDir, fmt.Sprintf("test-cert-1-%s.crt", testCertPEMFingerprint)):  []byte(testCertPEM),
			filepath.Join(caCertsDir, fmt.Sprintf("test-cert-2-%s.crt", testCertPEM2Fingerprint)): []byte(testCertPEM2),
			javaTruststorePaths[0]: createTruststore(map[string]string{
				"existing":                               testCertPEM2,
				"test-cert-1-" + testCertPEMFingerprint:  testCertPEM,
				"test-cert-2-" + testCertPEM2Fingerprint: testCertPEM2,
			}),
		},
	}, {
		// Package-provided certificate tests.
		name: "no packages with custom-ca-certificates",
		pkgs: []pkgEntry{{
			pkg: apktypes.Package{
				Name: "some-package", Version: "1.0.0", Arch: "x86_64",
				Provides: []string{"something-else"},
			},
		}},
	}, {
		name: "package without custom-ca-certificates provide is ignored",
		pkgs: []pkgEntry{{
			pkg: apktypes.Package{
				Name: "not-a-ca-pkg", Version: "1.0.0", Arch: "x86_64",
				Provides: []string{"something-else"},
			},
			files: []tar.Header{
				{Name: "usr", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "usr/share", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "usr/share/ca-certificates", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "usr/share/ca-certificates/sneaky", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "usr/share/ca-certificates/sneaky/sneaky-cert.crt", Mode: 0o644},
			},
		}},
		certData: map[string][]byte{
			"usr/share/ca-certificates/sneaky/sneaky-cert.crt": []byte(testCertPEM),
		},
	}, {
		name: "single package with two certs appends to bundle",
		pkgs: []pkgEntry{{
			pkg: apktypes.Package{
				Name: "ca-certs-1", Version: "1.0.0", Arch: "x86_64",
				Provides: []string{customCACertsProvides},
			},
			files: []tar.Header{
				{Name: "usr", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "usr/share", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "usr/share/ca-certificates", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "usr/share/ca-certificates/custom-1", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "usr/share/ca-certificates/custom-1/cert-a.crt", Mode: 0o644},
				{Name: "usr/share/ca-certificates/custom-1/cert-b.crt", Mode: 0o644},
			},
		}},
		certData: map[string][]byte{
			"usr/share/ca-certificates/custom-1/cert-a.crt": []byte(testCertPEM),
			"usr/share/ca-certificates/custom-1/cert-b.crt": []byte(testCertPEM2),
		},
		existingFiles: map[string][]byte{
			caBundlePaths[0]: {},
		},
		wantFiles: map[string][]byte{
			caBundlePaths[0]: []byte(testCertPEM + "\n" + testCertPEM2 + "\n"),
		},
	}, {
		name: "two packages with certs each appends to existing bundle",
		pkgs: []pkgEntry{{
			pkg: apktypes.Package{
				Name: "ca-certs-1", Version: "1.0.0", Arch: "x86_64",
				Provides: []string{customCACertsProvides},
			},
			files: []tar.Header{
				{Name: "usr", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "usr/share", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "usr/share/ca-certificates", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "usr/share/ca-certificates/custom-1", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "usr/share/ca-certificates/custom-1/cert-a.crt", Mode: 0o644},
			},
		}, {
			pkg: apktypes.Package{
				Name: "ca-certs-2", Version: "1.0.0", Arch: "x86_64",
				Provides: []string{customCACertsProvides},
			},
			files: []tar.Header{
				{Name: "usr", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "usr/share", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "usr/share/ca-certificates", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "usr/share/ca-certificates/custom-2", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "usr/share/ca-certificates/custom-2/cert-c.crt", Mode: 0o644},
			},
		}},
		certData: map[string][]byte{
			"usr/share/ca-certificates/custom-1/cert-a.crt": []byte(testCertPEM3),
			"usr/share/ca-certificates/custom-2/cert-c.crt": []byte(testCertPEM4),
		},
		existingFiles: map[string][]byte{
			caBundlePaths[0]: []byte("# Existing Bundle\n"),
		},
		wantFiles: map[string][]byte{
			caBundlePaths[0]: []byte("# Existing Bundle\n" + testCertPEM3 + "\n" + testCertPEM4 + "\n"),
		},
	}, {
		name: "non-cert files in package are ignored",
		pkgs: []pkgEntry{{
			pkg: apktypes.Package{
				Name: "ca-certs-1", Version: "1.0.0", Arch: "x86_64",
				Provides: []string{customCACertsProvides},
			},
			files: []tar.Header{
				{Name: "usr", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "usr/share", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "usr/share/ca-certificates", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "usr/share/ca-certificates/custom-1", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "usr/share/ca-certificates/custom-1/cert-a.crt", Mode: 0o644},
				{Name: "usr/share/ca-certificates/custom-1/README.md", Mode: 0o644},
			},
		}},
		certData: map[string][]byte{
			"usr/share/ca-certificates/custom-1/cert-a.crt": []byte(testCertPEM),
			"usr/share/ca-certificates/custom-1/README.md":  []byte("not a cert"),
		},
		existingFiles: map[string][]byte{
			caBundlePaths[0]: {},
		},
		wantFiles: map[string][]byte{
			caBundlePaths[0]: []byte(testCertPEM + "\n"),
		},
	}, {
		name: "package certs with existing Java truststore",
		pkgs: []pkgEntry{{
			pkg: apktypes.Package{
				Name: "ca-certs-1", Version: "1.0.0", Arch: "x86_64",
				Provides: []string{customCACertsProvides},
			},
			files: []tar.Header{
				{Name: "usr", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "usr/share", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "usr/share/ca-certificates", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "usr/share/ca-certificates/custom-1", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "usr/share/ca-certificates/custom-1/cert-a.crt", Mode: 0o644},
			},
		}},
		certData: map[string][]byte{
			"usr/share/ca-certificates/custom-1/cert-a.crt": []byte(testCertPEM),
		},
		existingFiles: map[string][]byte{
			caBundlePaths[0]: {},
			javaTruststorePaths[0]: createTruststore(map[string]string{
				"existing": testCertPEM2,
			}),
		},
		wantFiles: map[string][]byte{
			caBundlePaths[0]: []byte(testCertPEM + "\n"),
			javaTruststorePaths[0]: createTruststore(map[string]string{
				"existing":                      testCertPEM2,
				"pkg-" + testCertPEMFingerprint: testCertPEM,
			}),
		},
	}, {
		// Combined inline + package-provided certificate test.
		name: "inline and package certs both appended to bundle and truststore",
		cfg: &types.ImageCertificates{
			Additional: []types.AdditionalCertificateEntry{
				{Name: "inline-cert", Content: testCertPEM},
			},
		},
		pkgs: []pkgEntry{{
			pkg: apktypes.Package{
				Name: "ca-certs-1", Version: "1.0.0", Arch: "x86_64",
				Provides: []string{customCACertsProvides},
			},
			files: []tar.Header{
				{Name: "usr", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "usr/share", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "usr/share/ca-certificates", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "usr/share/ca-certificates/custom-1", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "usr/share/ca-certificates/custom-1/cert.crt", Mode: 0o644},
			},
		}},
		certData: map[string][]byte{
			"usr/share/ca-certificates/custom-1/cert.crt": []byte(testCertPEM3),
		},
		existingFiles: map[string][]byte{
			caBundlePaths[0]: []byte("# Existing Bundle\n"),
			javaTruststorePaths[0]: createTruststore(map[string]string{
				"existing": testCertPEM2,
			}),
		},
		wantFiles: map[string][]byte{
			// Inline certs are processed first, then package certs.
			caBundlePaths[0]: []byte("# Existing Bundle\n" + testCertPEM + "\n" + testCertPEM3 + "\n"),
			filepath.Join(caCertsDir, fmt.Sprintf("inline-cert-%s.crt", testCertPEMFingerprint)): []byte(testCertPEM),
			javaTruststorePaths[0]: createTruststore(map[string]string{
				"existing":                              testCertPEM2,
				"inline-cert-" + testCertPEMFingerprint: testCertPEM,
				"pkg-" + testCertPEM3Fingerprint:        testCertPEM3,
			}),
		},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := apkfs.NewMemFS()
			var apkInst *apk.APK

			// Initialize APK DB and register packages when testing package certs.
			if len(tt.pkgs) > 0 {
				var err error
				apkInst, err = apk.New(context.Background(), apk.WithFS(fsys), apk.WithIgnoreMknodErrors(true))
				if err != nil {
					t.Fatalf("failed to create APK: %v", err)
				}
				if err := apkInst.InitDB(context.Background()); err != nil {
					t.Fatalf("failed to init APK DB: %v", err)
				}
				for _, p := range tt.pkgs {
					if _, err := apkInst.AddInstalledPackage(&p.pkg, p.files); err != nil {
						t.Fatalf("failed to add installed package %s: %v", p.pkg.Name, err)
					}
				}
				for path, data := range tt.certData {
					if err := fsys.MkdirAll(filepath.Dir(path), 0o755); err != nil {
						t.Fatalf("failed to create dir for %s: %v", path, err)
					}
					if err := fsys.WriteFile(path, data, 0o644); err != nil {
						t.Fatalf("failed to write cert file %s: %v", path, err)
					}
				}
			}

			for path, content := range tt.existingFiles {
				if err := fsys.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatalf("failed to create directory for existing file %s: %v", path, err)
				}
				if err := fsys.WriteFile(path, content, 0o644); err != nil {
					t.Fatalf("failed to write existing file %s: %v", path, err)
				}
			}

			bc := &Context{
				o: options.Options{
					SourceDateEpoch: epoch,
				},
				ic: types.ImageConfiguration{
					Certificates: tt.cfg,
				},
				fs:  fsys,
				apk: apkInst,
			}

			err := bc.installCertificates(context.Background())
			if (err != nil) != tt.wantErr {
				t.Fatalf("installCertificates() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if len(tt.wantFiles) == 0 {
				// No-op case: verify primary CA bundle was NOT created/modified.
				if _, err := fsys.Stat(caBundlePaths[0]); err == nil {
					t.Errorf("expected no CA bundle to be created, but %s exists", caBundlePaths[0])
				}
				return
			}

			// Verify expected file contents and timestamps.
			for path, wantContent := range tt.wantFiles {
				data, err := fsys.ReadFile(path)
				if err != nil {
					t.Fatalf("failed to read expected file %s: %v", path, err)
				}
				if diff := cmp.Diff(wantContent, data); diff != "" {
					t.Errorf("file content mismatch for %s (-want +got):\n%s", path, diff)
				}
				stat, err := fsys.Stat(path)
				if err != nil {
					t.Fatalf("failed to stat file %s: %v", path, err)
				}
				if !stat.ModTime().Equal(epoch) {
					t.Errorf("file %s has mod time %v, want %v", path, stat.ModTime(), epoch)
				}
			}

			// Build a set of files that exist on the filesystem but are
			// not certificate output: APK DB files from InitDB and
			// package cert source files written during test setup.
			setupFiles := map[string]bool{}
			if apkInst != nil {
				for _, h := range apkInst.ListInitFiles() {
					setupFiles[strings.TrimPrefix(h.Name, "/")] = true
				}
			}
			for path := range tt.certData {
				setupFiles[path] = true
			}

			// Walk the entire filesystem to catch unexpected files.
			fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					t.Fatalf("error walking to %s: %v", path, err)
				}
				if d.IsDir() {
					return nil
				}
				if setupFiles[path] {
					return nil
				}
				if _, ok := tt.wantFiles[path]; !ok {
					t.Errorf("unexpected file created: %s", path)
				}
				return nil
			})
		})
	}
}
