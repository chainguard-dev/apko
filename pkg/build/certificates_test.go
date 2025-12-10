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
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"testing"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/options"

	"github.com/google/go-cmp/cmp"
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
	tests := []struct {
		name          string
		cfg           *types.ImageCertificates
		existingFiles map[string]string
		wantFiles     map[string]string
		wantErr       bool
	}{{
		name: "nil certificates config",
		cfg:  nil,
	}, {
		name: "valid single certificate without existing bundle",
		cfg: &types.ImageCertificates{
			Additional: []types.AdditionalCertificateEntry{
				{Name: "test-cert", Content: testCertPEM},
			},
		},
		existingFiles: map[string]string{},
		wantFiles: map[string]string{
			filepath.Join(caCertsDir, fmt.Sprintf("test-cert-%s.crt", testCertPEMFingerprint)): testCertPEM,
		},
	}, {
		name: "multiple certificate entries only one existing bundle",
		cfg: &types.ImageCertificates{
			Additional: []types.AdditionalCertificateEntry{
				{Name: "test-cert-1", Content: testCertPEM},
				{Name: "test-cert-2", Content: testCertPEM2},
			},
		},
		existingFiles: map[string]string{
			caBundlePaths[0]: "# Existing CA Bundle\n",
		},
		wantFiles: map[string]string{
			caBundlePaths[0]: "# Existing CA Bundle\n" + testCertPEM + "\n" + testCertPEM2 + "\n",
			filepath.Join(caCertsDir, fmt.Sprintf("test-cert-1-%s.crt", testCertPEMFingerprint)):  testCertPEM,
			filepath.Join(caCertsDir, fmt.Sprintf("test-cert-2-%s.crt", testCertPEM2Fingerprint)): testCertPEM2,
		},
	}, {
		name: "multiple certificate entries with multiple existing bundles",
		cfg: &types.ImageCertificates{
			Additional: []types.AdditionalCertificateEntry{
				{Name: "test-cert-1", Content: testCertPEM},
				{Name: "test-cert-2", Content: testCertPEM2},
			},
		},
		existingFiles: map[string]string{
			caBundlePaths[0]: "# Existing CA Bundle\n",
			caBundlePaths[1]: "# Another CA Bundle\n",
		},
		wantFiles: map[string]string{
			caBundlePaths[0]: "# Existing CA Bundle\n" + testCertPEM + "\n" + testCertPEM2 + "\n",
			caBundlePaths[1]: "# Another CA Bundle\n" + testCertPEM + "\n" + testCertPEM2 + "\n",
			filepath.Join(caCertsDir, fmt.Sprintf("test-cert-1-%s.crt", testCertPEMFingerprint)):  testCertPEM,
			filepath.Join(caCertsDir, fmt.Sprintf("test-cert-2-%s.crt", testCertPEM2Fingerprint)): testCertPEM2,
		},
	}, {
		name: "multiple certificate entries with identical names",
		cfg: &types.ImageCertificates{
			Additional: []types.AdditionalCertificateEntry{
				{Name: "test-cert", Content: testCertPEM},
				{Name: "test-cert", Content: testCertPEM2},
			},
		},
		existingFiles: map[string]string{
			caBundlePaths[0]: "# Existing CA Bundle\n",
		},
		wantFiles: map[string]string{
			caBundlePaths[0]: "# Existing CA Bundle\n" + testCertPEM + "\n" + testCertPEM2 + "\n",
			filepath.Join(caCertsDir, fmt.Sprintf("test-cert-%s.crt", testCertPEMFingerprint)):  testCertPEM,
			filepath.Join(caCertsDir, fmt.Sprintf("test-cert-%s.crt", testCertPEM2Fingerprint)): testCertPEM2,
		},
	}, {
		name: "certificate with additional metadata",
		cfg: &types.ImageCertificates{
			Additional: []types.AdditionalCertificateEntry{
				{Name: "test-cert", Content: "additional text\n" + testCertPEM},
			},
		},
		existingFiles: map[string]string{
			caBundlePaths[0]: "# Existing CA Bundle\n",
		},
		wantFiles: map[string]string{
			caBundlePaths[0]: "# Existing CA Bundle\n" + testCertPEM + "\n",
			filepath.Join(caCertsDir, fmt.Sprintf("test-cert-%s.crt", testCertPEMFingerprint)): testCertPEM,
		},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set SOURCE_DATE_EPOCH to avoid needing APK initialization
			t.Setenv("SOURCE_DATE_EPOCH", "0")

			fsys := apkfs.NewMemFS()
			bc := &Context{
				o: options.Options{},
				ic: types.ImageConfiguration{
					Certificates: tt.cfg,
				},
				fs: fsys,
			}

			for path, content := range tt.existingFiles {
				if err := fsys.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatalf("failed to create directory for existing file %s: %v", path, err)
				}
				if err := fsys.WriteFile(path, []byte(content), 0o644); err != nil {
					t.Fatalf("failed to write existing file %s: %v", path, err)
				}
			}

			err := bc.installCertificates(context.Background())
			if (err != nil) != tt.wantErr {
				t.Fatalf("installCertificates() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				// Expected error, nothing further to check
				return
			}
			if tt.cfg == nil || len(tt.cfg.Additional) == 0 {
				// Nothing further to check
				return
			}

			// Walk the entire filesystem to ensure we're checking contents for all
			// expected files.
			fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					t.Fatalf("error walking to %s: %v", path, err)
				}
				if d.IsDir() {
					return nil
				}

				wantContent, ok := tt.wantFiles[path]
				if !ok {
					t.Errorf("unexpected file created: %s", path)
					return nil
				}

				data, err := fsys.ReadFile(path)
				if err != nil {
					t.Fatalf("failed to read expected file %s: %v", path, err)
				}
				gotContent := string(data)
				if diff := cmp.Diff(wantContent, gotContent); diff != "" {
					t.Errorf("file content mismatch for %s (-want +got):\n%s", path, diff)
				}
				return nil
			})
		})
	}
}
