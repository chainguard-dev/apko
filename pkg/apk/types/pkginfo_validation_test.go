package types

import (
	"strings"
	"testing"
)

// apk-tools reads .PKGINFO as a plain "key = value" line splitter with no
// quoting (src/package.c). apko parses it with gopkg.in/ini.v1, which honours
// backquoted and triple-quoted multi-line values by default. That divergence
// means a crafted .PKGINFO can smuggle an embedded newline into a field value
// that apk-tools would never produce and never see.
//
// It matters because those values are written verbatim into the apk installed
// database, a newline-delimited "<token>:<value>" format, so an embedded
// newline lets a package forge additional database records -- and those records
// propagate into the generated SBOM.
func TestParsePackageInfoRejectsEmbeddedNewlines(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			name: "triple-quoted pkgdesc forging a package record",
			body: "pkgname = innocent\npkgver = 1.0\npkgdesc = \"\"\"a normal package\n\nP:totally-not-malware\nV:9.9.9\"\"\"\n",
		},
		{
			name: "backquoted pkgdesc",
			body: "pkgname = innocent\npkgver = 1.0\npkgdesc = `first\nsecond`\n",
		},
		{
			name: "triple-quoted pkgname",
			body: "pkgname = \"\"\"innocent\nP:forged\"\"\"\npkgver = 1.0\n",
		},
		{
			name: "triple-quoted license",
			body: "pkgname = innocent\npkgver = 1.0\nlicense = \"\"\"MIT\nP:forged\"\"\"\n",
		},
		{
			name: "triple-quoted url",
			body: "pkgname = innocent\npkgver = 1.0\nurl = \"\"\"http://example.com\nP:forged\"\"\"\n",
		},
		{
			name: "triple-quoted origin",
			body: "pkgname = innocent\npkgver = 1.0\norigin = \"\"\"innocent\nP:forged\"\"\"\n",
		},
		{
			name: "triple-quoted maintainer",
			body: "pkgname = innocent\npkgver = 1.0\nmaintainer = \"\"\"someone\nP:forged\"\"\"\n",
		},
		{
			name: "triple-quoted commit",
			body: "pkgname = innocent\npkgver = 1.0\ncommit = \"\"\"abc123\nP:forged\"\"\"\n",
		},
		{
			name: "backquoted depend, a shadowed slice field",
			body: "pkgname = innocent\npkgver = 1.0\ndepend = `libc\nP:forged`\n",
		},
		{
			name: "backquoted provides, a shadowed slice field",
			body: "pkgname = innocent\npkgver = 1.0\nprovides = `so:libfoo.so.1\nP:forged`\n",
		},
		{
			name: "backquoted install_if, a shadowed slice field",
			body: "pkgname = innocent\npkgver = 1.0\ninstall_if = `foo\nP:forged`\n",
		},
		{
			name: "backquoted replaces, a shadowed slice field",
			body: "pkgname = innocent\npkgver = 1.0\nreplaces = `bar\nP:forged`\n",
		},
		{
			name: "backquoted triggers, reaches the triggers database",
			body: "pkgname = innocent\npkgver = 1.0\ntriggers = `/usr/lib\nQ1AAAA= /etc`\n",
		},
		{
			name: "carriage return in a triple-quoted value",
			body: "pkgname = innocent\npkgver = 1.0\npkgdesc = \"\"\"a\rb\"\"\"\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pi, err := ParsePackageInfo(strings.NewReader(tc.body))
			if err == nil {
				t.Fatalf("ParsePackageInfo accepted a multi-line value, want rejection; parsed = %+v", pi)
			}
			if !strings.Contains(err.Error(), "newline") {
				t.Errorf("error = %q, want it to mention %q", err.Error(), "newline")
			}
		})
	}
}

// The rejection must not cost legitimate .PKGINFO files. apk-tools produces
// plain single-line values; backslash continuation is joined by go-ini without
// retaining the newline and so stays acceptable.
func TestParsePackageInfoAcceptsLegitimateValues(t *testing.T) {
	cases := []struct {
		name  string
		body  string
		check func(t *testing.T, pi *PackageInfo)
	}{
		{
			name: "ordinary single-line values",
			body: "pkgname = foo\npkgver = 1.2.3-r0\narch = x86_64\npkgdesc = A perfectly ordinary package\nlicense = Apache-2.0\nurl = https://example.com\n",
			check: func(t *testing.T, pi *PackageInfo) {
				if pi.Name != "foo" || pi.Version != "1.2.3-r0" {
					t.Errorf("Name/Version = %q/%q, want foo/1.2.3-r0", pi.Name, pi.Version)
				}
				if pi.Description != "A perfectly ordinary package" {
					t.Errorf("Description = %q", pi.Description)
				}
			},
		},
		{
			name: "UTF-8 in description and maintainer",
			body: "pkgname = foo\npkgver = 1.0\npkgdesc = Ünïcödé description with 日本語 and 🔒\nmaintainer = Someone <someone@example.com>\n",
			check: func(t *testing.T, pi *PackageInfo) {
				if !strings.Contains(pi.Description, "日本語") {
					t.Errorf("Description lost UTF-8: %q", pi.Description)
				}
			},
		},
		{
			name: "tabs and colons in a description are fine",
			body: "pkgname = foo\npkgver = 1.0\npkgdesc = a\tdescription: with punctuation\n",
			check: func(t *testing.T, pi *PackageInfo) {
				if !strings.Contains(pi.Description, "\t") {
					t.Errorf("Description lost the tab: %q", pi.Description)
				}
			},
		},
		{
			name: "shadowed slice fields with several entries",
			body: "pkgname = foo\npkgver = 1.0\ndepend = libc\ndepend = libssl\nprovides = so:libfoo.so.1\nreplaces = oldfoo\n",
			check: func(t *testing.T, pi *PackageInfo) {
				if len(pi.Dependencies) != 2 {
					t.Errorf("Dependencies = %v, want 2 entries", pi.Dependencies)
				}
			},
		},
		{
			name: "numeric and hash fields",
			body: "pkgname = foo\npkgver = 1.0\nsize = 12345\nbuilddate = 1700000000\nprovider_priority = 10\ndatahash = deadbeef\n",
			check: func(t *testing.T, pi *PackageInfo) {
				if pi.Size != 12345 || pi.BuildDate != 1700000000 {
					t.Errorf("Size/BuildDate = %d/%d", pi.Size, pi.BuildDate)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pi, err := ParsePackageInfo(strings.NewReader(tc.body))
			if err != nil {
				t.Fatalf("ParsePackageInfo(%s) = %v, want success", tc.name, err)
			}
			tc.check(t, pi)
		})
	}
}
