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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/github/go-spdx/v2/spdxexp"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/apk/apk"
	apkfs "chainguard.dev/apko/pkg/apk/fs"
)

func TestLicenseExpression(t *testing.T) {
	ref := func(id, text string) []LicensingInfo {
		return []LicensingInfo{{LicenseID: id, ExtractedText: text}}
	}
	for _, tt := range []struct {
		name string
		raw  string
		want string
		refs []LicensingInfo
	}{{
		name: "empty field is no assertion",
		raw:  "",
		want: NOASSERTION,
	}, {
		name: "listed license is kept",
		raw:  "MIT",
		want: "MIT",
	}, {
		name: "valid expression is kept",
		raw:  "MIT AND BSD-2-Clause",
		want: "MIT AND BSD-2-Clause",
	}, {
		name: "listed exception is kept",
		raw:  "GPL-2.0-or-later WITH Autoconf-exception-2.0",
		want: "GPL-2.0-or-later WITH Autoconf-exception-2.0",
	}, {
		name: "nested expression is kept",
		raw:  "(MIT OR Apache-2.0) AND Zlib",
		want: "(MIT OR Apache-2.0) AND Zlib",
	}, {
		name: "lowercase operator is uppercased",
		raw:  "BSD-2-Clause AND CC-BY-SA-4.0 and CC0-1.0",
		want: "BSD-2-Clause AND CC-BY-SA-4.0 AND CC0-1.0",
	}, {
		name: "space-separated list is joined with AND",
		raw:  "Apache-2.0 MIT",
		want: "Apache-2.0 AND MIT",
	}, {
		name: "unlisted license in a list becomes a reference",
		raw:  "BSD MIT",
		want: "LicenseRef-apk-BSD AND MIT",
		refs: ref("LicenseRef-apk-BSD", "BSD"),
	}, {
		name: "unlisted license in an expression becomes a reference",
		raw:  "(BSD-2-Clause OR custom) AND MIT",
		want: "(BSD-2-Clause OR LicenseRef-apk-custom) AND MIT",
		refs: ref("LicenseRef-apk-custom", "custom"),
	}, {
		name: "repeated unlisted license is referenced once",
		raw:  "custom AND GPL-2.0-only AND custom",
		want: "LicenseRef-apk-custom AND GPL-2.0-only AND LicenseRef-apk-custom",
		refs: ref("LicenseRef-apk-custom", "custom"),
	}, {
		name: "unlisted license alone becomes a reference",
		raw:  "custom:chromiumos",
		want: "LicenseRef-apk-custom-chromiumos",
		refs: ref("LicenseRef-apk-custom-chromiumos", "custom:chromiumos"),
	}, {
		name: "list naming no listed license is one name",
		raw:  "Public Domain",
		want: "LicenseRef-apk-Public-Domain",
		refs: ref("LicenseRef-apk-Public-Domain", "Public Domain"),
	}, {
		name: "malformed expression becomes one reference",
		raw:  "MIT AND",
		want: "LicenseRef-apk-MIT-AND",
		refs: ref("LicenseRef-apk-MIT-AND", "MIT AND"),
	}, {
		name: "unlisted exception becomes one reference",
		raw:  "GPL-2.0-or-later WITH custom-exception",
		want: "LicenseRef-apk-GPL-2.0-or-later-WITH-custom-exception",
		refs: ref("LicenseRef-apk-GPL-2.0-or-later-WITH-custom-exception", "GPL-2.0-or-later WITH custom-exception"),
	}} {
		t.Run(tt.name, func(t *testing.T) {
			got, refs := licenseExpression(tt.raw)
			if got != tt.want {
				t.Errorf("expression: got = %q, want = %q", got, tt.want)
			}
			if diff := cmp.Diff(tt.refs, refs); diff != "" {
				t.Errorf("references (-want, +got):\n%s", diff)
			}
			if got != NOASSERTION {
				if ok, bad := spdxexp.ValidateLicenses([]string{got}); !ok {
					t.Errorf("%q is not a valid SPDX license expression: %q", got, bad)
				}
			}
		})
	}
}

func TestLicenseExpressionUnnamed(t *testing.T) {
	got, refs := licenseExpression("???")
	require.True(t, strings.HasPrefix(got, "LicenseRef-apk-"), got)
	require.Equal(t, []LicensingInfo{{LicenseID: got, ExtractedText: "???"}}, refs)
	ok, bad := spdxexp.ValidateLicenses([]string{got})
	require.True(t, ok, bad)
}

func TestInstalledPackageLicense(t *testing.T) {
	fsys := apkfs.NewMemFS()
	opts := testOpts(fsys)
	gpl := installed("gpl-tool", "1.0.0-r0")
	gpl.License = "GPL-3.0-or-later custom"
	vendor := installed("vendor-tool", "2.0.0-r0")
	vendor.License = "custom"
	opts.Packages = []*apk.InstalledPackage{gpl, vendor}

	out := filepath.Join(t.TempDir(), "sbom.spdx.json")
	require.NoError(t, New().Generate(t.Context(), opts, out))
	b, err := os.ReadFile(out)
	require.NoError(t, err)
	var doc Document
	require.NoError(t, json.Unmarshal(b, &doc))

	declared := map[string]string{}
	for _, p := range doc.Packages {
		declared[p.Name] = p.LicenseDeclared
	}
	require.Equal(t, "GPL-3.0-or-later AND LicenseRef-apk-custom", declared["gpl-tool"])
	require.Equal(t, "LicenseRef-apk-custom", declared["vendor-tool"])
	require.Equal(t, []LicensingInfo{{LicenseID: "LicenseRef-apk-custom", ExtractedText: "custom"}}, doc.LicensingInfos)
}
