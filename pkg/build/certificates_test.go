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
	testCertPEM = `-----BEGIN CERTIFICATE-----
MIID7zCCAtegAwIBAgIUYUfEDHPlltgSgE0RgsV1LP6+FgkwDQYJKoZIhvcNAQEL
BQAwgYYxCzAJBgNVBAYTAlhYMRIwEAYDVQQIDAlTdGF0ZU5hbWUxETAPBgNVBAcM
CENpdHlOYW1lMRQwEgYDVQQKDAtDb21wYW55TmFtZTEbMBkGA1UECwwSQ29tcGFu
eVNlY3Rpb25OYW1lMR0wGwYDVQQDDBRDb21tb25OYW1lT3JIb3N0bmFtZTAeFw0y
NTEyMTAxMjE0NTBaFw0zNTEyMDgxMjE0NTBaMIGGMQswCQYDVQQGEwJYWDESMBAG
A1UECAwJU3RhdGVOYW1lMREwDwYDVQQHDAhDaXR5TmFtZTEUMBIGA1UECgwLQ29t
cGFueU5hbWUxGzAZBgNVBAsMEkNvbXBhbnlTZWN0aW9uTmFtZTEdMBsGA1UEAwwU
Q29tbW9uTmFtZU9ySG9zdG5hbWUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDiby0uic7Oe81+L5Ilyswx9/cHCIjkjMQyGbpVxbjIaMwZZM66Qi8C5yhc
zBrJxhmhrjtbLLiCpbfcshoH5IbyWxOUnDbLZMnu82cv0gPC0kd82enNF69E/QAV
vJ5KVTE0ursEQlIm+0UtD1PTb3D91HZorWm2oGUHwnLQJTlFvPhjeREZoM4IgkNR
ND7Yu0kPJWsHq9v0bfADB28VlyhAqQgqJIMBzA9wNtGeSvvCZIolyD96D2mY3BU5
3CEoghLWjzQuAh5338mjPCa2S+M7pL4j8MnFXwkKDKsfp2TsUl5JjET7cZ9kBJIS
81dyAcS11+uZ48afKPaK7uZwa6CdAgMBAAGjUzBRMB0GA1UdDgQWBBTOdudo+VjH
X2CV3eGwmgTp43G61jAfBgNVHSMEGDAWgBTOdudo+VjHX2CV3eGwmgTp43G61jAP
BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAWpSJALmn/60zlTJX6
6tpNXJlpJIT6AGX4PFcdDptsIo+8icfVP1bY95eqvyLdVa0uX32UeGmbpGQQKRNz
hDc2AWaqWpTQia8kCVuj0tSIDtE1lQLsynXSyopiN+pKxlFrBUGJDhHsz648eRvC
NtONZz1Fe0MPAkwIHI/4HyfcNyvB79ZEKSQS8EFZkdr+Wq/7YFGJY01lwqoVFBdp
5TKLxolh7yeMeBjKlY67gCft488nNCVD8pVPvW9MSr9it/x2/WFgyXP796E+Yf92
m+4Kz2EqjAF4HRZRkCif3TO2ogEAa34mI5A6abz852DXIQaOCKVc6qrc/qcYhuZg
zgX7
-----END CERTIFICATE-----
`
	testCertPEMFingerprint = "940cc1b798d3b57b1067751575e7a71ce9cdad38dc1d7f5efb832f6ceec1ad10"

	testCertPEM2 = `-----BEGIN CERTIFICATE-----
MIID7zCCAtegAwIBAgIUf22avPx7RM/YDqEvYEMOL89FltAwDQYJKoZIhvcNAQEL
BQAwgYYxCzAJBgNVBAYTAlhYMRIwEAYDVQQIDAlTdGF0ZU5hbWUxETAPBgNVBAcM
CENpdHlOYW1lMRQwEgYDVQQKDAtDb21wYW55TmFtZTEbMBkGA1UECwwSQ29tcGFu
eVNlY3Rpb25OYW1lMR0wGwYDVQQDDBRDb21tb25OYW1lT3JIb3N0bmFtZTAeFw0y
NTEyMTAxMjE1MjNaFw0zNTEyMDgxMjE1MjNaMIGGMQswCQYDVQQGEwJYWDESMBAG
A1UECAwJU3RhdGVOYW1lMREwDwYDVQQHDAhDaXR5TmFtZTEUMBIGA1UECgwLQ29t
cGFueU5hbWUxGzAZBgNVBAsMEkNvbXBhbnlTZWN0aW9uTmFtZTEdMBsGA1UEAwwU
Q29tbW9uTmFtZU9ySG9zdG5hbWUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQCrpUPF6oyrWr/s2LmYMIKAjrpAj/zXiTqRIXsCtTjeRZdeg4PsZxhRM3uY
wIeIbtGrt0/NfXEIa6ykwsOoeGkYweMUQuzMo7SlU7lxVe1vWwVg+wrf+GMkGTSV
YdQeN+YKYNVmC/8XcM3FuvHctgzfez3eKxj/wvwnBYgaFV0ld6YX9onxcdvzSpby
PUZwJ8788U9D1zx9s3Q7e44xM0nQjZvtXFBxN6gWJDC9OlqdWyoPfEhf3rZnowdn
TP5HlFc198egDzSsATQrS/oM2LoFgLozJPZf2SuZE3KCGkx9gax+JkfIvJefw2D5
U1N633wENcUh3MpzKXnqjBd51Zy1AgMBAAGjUzBRMB0GA1UdDgQWBBRWsRCy08Dd
muT+W9MwqF9eVJOyrDAfBgNVHSMEGDAWgBRWsRCy08DdmuT+W9MwqF9eVJOyrDAP
BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQA7sZy5V2SwvB9mwGCC
fNQYH/tJ1ZCB8XV56Mh/BzIV32TYzGaFvOQVyKRIo5P6ud3scWPkOMzxcosUowJC
XJj6AMUMSBsVc/HtI0sc1vZHaKGiNAjyD2rEjbp5DAdkYvuwq+KNYruU6ObnF2Uy
bERl/rg4st147qQzevXiGIJqEmA2LBRGEWLkL7IXxsfKLWHtLbZQtsIZWiPQdiUQ
dNXihLf/ydBFFZwBTxKYTqU/eK/NzPvUw2AjBrYbv6s95Bp/oNtHYDGAVel48U+0
P5XXAiczPjIoNh1f3RXBVPg+rGZgbLpmMtkAl438bcm9A5CcFZXTm2vOBCh9HeHb
66vN
-----END CERTIFICATE-----
`
	testCertPEM2Fingerprint = "9bcacef46265abf1bed286c4b64619ed77293a98fea23cb72ae69a4e329328d9"
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
			Additional: []types.CertificateEntry{
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
			Additional: []types.CertificateEntry{
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
			Additional: []types.CertificateEntry{
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
			Additional: []types.CertificateEntry{
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
			Additional: []types.CertificateEntry{
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
