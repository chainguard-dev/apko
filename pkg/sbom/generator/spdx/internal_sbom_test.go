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

package spdx

import (
	"archive/tar"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/apk/apk"
	apkfs "chainguard.dev/apko/pkg/apk/fs"
)

// installed returns an installed package whose database entry lists owns.
func installed(name, version string, owns ...string) *apk.InstalledPackage {
	ipkg := &apk.InstalledPackage{Name: name, Version: version, Arch: "x86_64", License: "MIT"}
	for _, p := range owns {
		ipkg.Files = append(ipkg.Files, tar.Header{Name: p})
	}
	return ipkg
}

func sbomAt(nameVersion string) string {
	return "var/lib/db/sbom/" + nameVersion + ".spdx.json"
}

func apkRef(name, version string) ExternalRef {
	return ExternalRef{
		Category: "PACKAGE_MANAGER",
		Type:     "purl",
		Locator:  "pkg:apk/wolfi/" + name + "@" + version + "?arch=x86_64",
	}
}

func record(name, version string, refs ...ExternalRef) Package {
	return Package{
		ID:           stringToIdentifier("SPDXRef-Package-" + name + "-" + version),
		Name:         name,
		Version:      version,
		ExternalRefs: refs,
	}
}

// fixture reads a real apk SBOM from testdata.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "apk_sboms", name))
	require.NoError(t, err)
	return b
}

// internalSBOM encodes a document that describes primary and reaches each of reachable from it.
func internalSBOM(t *testing.T, primary Package, reachable ...Package) []byte {
	t.Helper()
	doc := Document{
		ID:                "SPDXRef-DOCUMENT",
		DocumentDescribes: []string{primary.ID},
		Packages:          append([]Package{primary}, reachable...),
	}
	for _, r := range reachable {
		doc.Relationships = append(doc.Relationships, Relationship{
			Element: primary.ID, Type: "GENERATED_FROM", Related: r.ID,
		})
	}
	b, err := json.Marshal(doc)
	require.NoError(t, err)
	return b
}

func TestInternalSBOMIdentity(t *testing.T) {
	source := Package{
		ID:      "SPDXRef-Package-github.com-example-foo-v1.0.0",
		Name:    "foo-src",
		Version: "v1.0.0",
		ExternalRefs: []ExternalRef{{
			Category: "PACKAGE_MANAGER", Type: "purl", Locator: "pkg:github/example/foo@v1.0.0",
		}, {
			Category: "SECURITY", Type: "cpe23Type", Locator: "cpe:2.3:a:example:foo:1.0.0:*:*:*:*:*:*:*",
		}},
		Checksums: []Checksum{{Algorithm: "SHA1", Value: "a1"}, {Algorithm: "SHA256", Value: "b2"}},
	}
	// Builds of one upstream source can disagree on its license or reference order.
	relicensed := source
	relicensed.LicenseDeclared = "BSD-3-Clause"
	reordered := source
	reordered.ExternalRefs = slices.Clone(source.ExternalRefs)
	slices.Reverse(reordered.ExternalRefs)
	reordered.Checksums = slices.Clone(source.Checksums)
	slices.Reverse(reordered.Checksums)
	repurled := source
	repurled.ExternalRefs = []ExternalRef{{
		Category: "PACKAGE_MANAGER", Type: "purl", Locator: "pkg:github/example/foo@v9.9.9",
	}}
	rehashed := source
	rehashed.Checksums = []Checksum{{Algorithm: "SHA256", Value: "c3"}}
	foo := record("foo", "1.0.0-r0", apkRef("foo", "1.0.0-r0"))
	openssl := record("openssl", "3.0.1-r0", apkRef("openssl", "3.0.1-r0"))

	for _, tt := range []struct {
		name    string
		pkgs    []*apk.InstalledPackage
		files   map[string][]byte
		present []string // name@version entries the image SBOM must hold
		absent  []string // name@version entries it must not hold
		purls   []string // PURLs it must hold
		wantErr string
	}{{
		name:    "matching SBOM is copied with its reachable packages",
		pkgs:    []*apk.InstalledPackage{installed("foo", "1.0.0-r0", sbomAt("foo-1.0.0-r0"))},
		files:   map[string][]byte{sbomAt("foo-1.0.0-r0"): internalSBOM(t, foo, source)},
		present: []string{"foo@1.0.0-r0", "foo-src@v1.0.0"},
	}, {
		name:    "SBOM version without the epoch is accepted",
		pkgs:    []*apk.InstalledPackage{installed("foo", "1.0.0-r0", sbomAt("foo-1.0.0-r0"))},
		files:   map[string][]byte{sbomAt("foo-1.0.0-r0"): internalSBOM(t, record("foo", "1.0.0"))},
		present: []string{"foo@1.0.0"},
	}, {
		name: "SBOM cataloging the package's own apk entry is accepted",
		pkgs: []*apk.InstalledPackage{
			installed("wolfi-baselayout", "20230201-r30", sbomAt("wolfi-baselayout-20230201-r30")),
		},
		files: map[string][]byte{
			sbomAt("wolfi-baselayout-20230201-r30"): fixture(t, "wolfi-baselayout-20230201-r30.spdx.json"),
		},
		present: []string{"wolfi-baselayout@20230201-r30"},
		purls: []string{
			"pkg:apk/wolfi/wolfi-baselayout@20230201-r30?arch=x86_64&origin=wolfi-baselayout",
		},
	}, {
		name:    "package without an SBOM is described from the installed database",
		pkgs:    []*apk.InstalledPackage{installed("no-sbom", "1.0.0-r0", "usr/bin/no-sbom")},
		present: []string{"no-sbom@1.0.0-r0"},
		purls:   []string{"pkg:apk/unknown/no-sbom@1.0.0-r0?arch=x86_64"},
	}, {
		name: "SBOM owned by another package is ignored",
		pkgs: []*apk.InstalledPackage{
			installed("busybox", "1.36.1-r0", "bin/busybox"),
			installed("planter", "1.0.0-r0", sbomAt("planter-1.0.0-r0"), sbomAt("busybox-1.36.1-r0")),
		},
		files: map[string][]byte{
			sbomAt("planter-1.0.0-r0"):  internalSBOM(t, record("planter", "1.0.0-r0")),
			sbomAt("busybox-1.36.1-r0"): internalSBOM(t, record("busybox", "9.9.9-r0")),
		},
		present: []string{"busybox@1.36.1-r0", "planter@1.0.0-r0"},
		absent:  []string{"busybox@9.9.9-r0"},
	}, {
		name: "SBOM describing another package fails",
		pkgs: []*apk.InstalledPackage{
			installed("evil-helper", "1.0.0-r0", sbomAt("evil-helper-1.0.0-r0")),
		},
		files: map[string][]byte{
			sbomAt("evil-helper-1.0.0-r0"): internalSBOM(t,
				record("openssl", "9.9.9-r0", apkRef("openssl", "9.9.9-r0"))),
		},
		wantErr: "evil-helper",
	}, {
		name:    "SBOM describing another version fails",
		pkgs:    []*apk.InstalledPackage{installed("foo", "1.0.0-r0", sbomAt("foo-1.0.0-r0"))},
		files:   map[string][]byte{sbomAt("foo-1.0.0-r0"): internalSBOM(t, record("foo", "2.0.0-r0"))},
		wantErr: "foo",
	}, {
		name: "described apk PURL naming another package fails",
		pkgs: []*apk.InstalledPackage{installed("foo", "1.0.0-r0", sbomAt("foo-1.0.0-r0"))},
		files: map[string][]byte{
			sbomAt("foo-1.0.0-r0"): internalSBOM(t,
				record("foo", "1.0.0-r0", apkRef("openssl", "3.0.1-r0"))),
		},
		wantErr: "foo",
	}, {
		name: "reachable package with another package's apk PURL fails",
		pkgs: []*apk.InstalledPackage{installed("foo", "1.0.0-r0", sbomAt("foo-1.0.0-r0"))},
		files: map[string][]byte{
			sbomAt("foo-1.0.0-r0"): internalSBOM(t, foo,
				record("openssl", "9.9.9-r0", apkRef("openssl", "9.9.9-r0"))),
		},
		wantErr: "foo",
	}, {
		name: "reachable package named for the package with another apk PURL fails",
		pkgs: []*apk.InstalledPackage{installed("foo", "1.0.0-r0", sbomAt("foo-1.0.0-r0"))},
		files: map[string][]byte{
			sbomAt("foo-1.0.0-r0"): internalSBOM(t, foo, Package{
				ID: "SPDXRef-Package-apk-foo-0123", Name: "foo", Version: "1.0.0-r0",
				ExternalRefs: []ExternalRef{apkRef("openssl", "3.0.1-r0")},
			}),
		},
		wantErr: "foo",
	}, {
		name: "reachable package using an installed package's SPDX ID fails",
		pkgs: []*apk.InstalledPackage{
			installed("aaa", "1.0.0-r0", sbomAt("aaa-1.0.0-r0")),
			installed("openssl", "3.0.1-r0", sbomAt("openssl-3.0.1-r0")),
		},
		files: map[string][]byte{
			sbomAt("aaa-1.0.0-r0"): internalSBOM(t, record("aaa", "1.0.0-r0"),
				Package{ID: openssl.ID, Name: "openssl-src", Version: "3.5.0"}),
			sbomAt("openssl-3.0.1-r0"): internalSBOM(t, openssl),
		},
		wantErr: "aaa",
	}, {
		name: "described package using another installed package's SPDX ID fails",
		pkgs: []*apk.InstalledPackage{
			installed("aaa", "1.0.0-r0", sbomAt("aaa-1.0.0-r0")),
			installed("openssl", "3.0.1-r0", sbomAt("openssl-3.0.1-r0")),
		},
		files: map[string][]byte{
			sbomAt("aaa-1.0.0-r0"): internalSBOM(t,
				Package{ID: openssl.ID, Name: "aaa", Version: "1.0.0-r0"}),
			sbomAt("openssl-3.0.1-r0"): internalSBOM(t, openssl),
		},
		wantErr: "aaa",
	}, {
		name: "shared SPDX ID with a different license is kept once",
		pkgs: []*apk.InstalledPackage{
			installed("foo", "1.0.0-r0", sbomAt("foo-1.0.0-r0")),
			installed("bar", "1.0.0-r0", sbomAt("bar-1.0.0-r0")),
		},
		files: map[string][]byte{
			sbomAt("foo-1.0.0-r0"): internalSBOM(t, foo, source),
			sbomAt("bar-1.0.0-r0"): internalSBOM(t, record("bar", "1.0.0-r0"), relicensed),
		},
		present: []string{"foo-src@v1.0.0", "bar@1.0.0-r0"},
	}, {
		name: "shared SPDX ID with reordered references and checksums is kept once",
		pkgs: []*apk.InstalledPackage{
			installed("foo", "1.0.0-r0", sbomAt("foo-1.0.0-r0")),
			installed("bar", "1.0.0-r0", sbomAt("bar-1.0.0-r0")),
		},
		files: map[string][]byte{
			sbomAt("foo-1.0.0-r0"): internalSBOM(t, foo, source),
			sbomAt("bar-1.0.0-r0"): internalSBOM(t, record("bar", "1.0.0-r0"), reordered),
		},
		present: []string{"foo-src@v1.0.0", "bar@1.0.0-r0"},
	}, {
		name: "shared SPDX ID with a different version fails",
		pkgs: []*apk.InstalledPackage{
			installed("foo", "1.0.0-r0", sbomAt("foo-1.0.0-r0")),
			installed("bar", "1.0.0-r0", sbomAt("bar-1.0.0-r0")),
		},
		files: map[string][]byte{
			sbomAt("foo-1.0.0-r0"): internalSBOM(t, foo, source),
			sbomAt("bar-1.0.0-r0"): internalSBOM(t, record("bar", "1.0.0-r0"),
				Package{ID: source.ID, Name: "foo-src", Version: "v9.9.9"}),
		},
		wantErr: source.ID,
	}, {
		name: "shared SPDX ID with a different PURL fails",
		pkgs: []*apk.InstalledPackage{
			installed("foo", "1.0.0-r0", sbomAt("foo-1.0.0-r0")),
			installed("bar", "1.0.0-r0", sbomAt("bar-1.0.0-r0")),
		},
		files: map[string][]byte{
			sbomAt("foo-1.0.0-r0"): internalSBOM(t, foo, source),
			sbomAt("bar-1.0.0-r0"): internalSBOM(t, record("bar", "1.0.0-r0"), repurled),
		},
		wantErr: source.ID,
	}, {
		name: "shared SPDX ID with a different checksum fails",
		pkgs: []*apk.InstalledPackage{
			installed("foo", "1.0.0-r0", sbomAt("foo-1.0.0-r0")),
			installed("bar", "1.0.0-r0", sbomAt("bar-1.0.0-r0")),
		},
		files: map[string][]byte{
			sbomAt("foo-1.0.0-r0"): internalSBOM(t, foo, source),
			sbomAt("bar-1.0.0-r0"): internalSBOM(t, record("bar", "1.0.0-r0"), rehashed),
		},
		wantErr: source.ID,
	}, {
		name:    "malformed SBOM fails",
		pkgs:    []*apk.InstalledPackage{installed("broken", "1.0.0-r0", sbomAt("broken-1.0.0-r0"))},
		files:   map[string][]byte{sbomAt("broken-1.0.0-r0"): []byte("{not json")},
		wantErr: "broken",
	}, {
		name: "SBOM that describes nothing fails",
		pkgs: []*apk.InstalledPackage{installed("foo", "1.0.0-r0", sbomAt("foo-1.0.0-r0"))},
		files: map[string][]byte{
			sbomAt("foo-1.0.0-r0"): []byte(`{"SPDXID":"SPDXRef-DOCUMENT","packages":[` +
				`{"SPDXID":"SPDXRef-Package-foo-1.0.0-r0","name":"foo","versionInfo":"1.0.0-r0"}]}`),
		},
		wantErr: "foo",
	}, {
		name: "SBOM describing a missing element fails",
		pkgs: []*apk.InstalledPackage{installed("foo", "1.0.0-r0", sbomAt("foo-1.0.0-r0"))},
		files: map[string][]byte{
			sbomAt("foo-1.0.0-r0"): []byte(`{"SPDXID":"SPDXRef-DOCUMENT",` +
				`"documentDescribes":["SPDXRef-Package-ghost"],"packages":[]}`),
		},
		wantErr: "foo",
	}} {
		t.Run(tt.name, func(t *testing.T) {
			fsys := apkfs.NewMemFS()
			require.NoError(t, fsys.MkdirAll("var/lib/db/sbom", 0o755))
			for p, b := range tt.files {
				require.NoError(t, fsys.WriteFile(p, b, 0o644))
			}
			opts := testOpts(fsys)
			opts.Packages = tt.pkgs

			out := filepath.Join(t.TempDir(), "sbom.spdx.json")
			err := New().Generate(t.Context(), opts, out)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			b, err := os.ReadFile(out)
			require.NoError(t, err)
			var doc Document
			require.NoError(t, json.Unmarshal(b, &doc))
			entries := map[string]struct{}{}
			purls := map[string]struct{}{}
			for _, p := range doc.Packages {
				entries[p.Name+"@"+p.Version] = struct{}{}
				for _, ref := range p.ExternalRefs {
					purls[ref.Locator] = struct{}{}
				}
			}
			for _, want := range tt.present {
				require.Contains(t, entries, want)
			}
			for _, notWant := range tt.absent {
				require.NotContains(t, entries, notWant)
			}
			for _, want := range tt.purls {
				require.Contains(t, purls, want)
			}
		})
	}
}

// statErrFS fails every Stat, as a filesystem that denies access would.
type statErrFS struct{ apkfs.FullFS }

func (statErrFS) Stat(string) (fs.FileInfo, error) { return nil, fs.ErrPermission }

func TestLocateApkSBOMStatError(t *testing.T) {
	ipkg := installed("foo", "1.0.0-r0", sbomAt("foo-1.0.0-r0"))
	_, err := locateApkSBOM(statErrFS{apkfs.NewMemFS()}, ipkg)
	require.ErrorIs(t, err, fs.ErrPermission)
}
