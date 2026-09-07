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

package apk

import (
	"regexp"
	"strings"
	"testing"
)

// regexResolvePackageNameVersionPin is the previous, regex-based
// implementation of ResolvePackageNameVersionPin, kept as the oracle the
// hand-written parser is checked against.
func regexResolvePackageNameVersionPin(pkgName string) ParsedConstraint {
	endsWithReleaseStr := regexp.MustCompile(`-r\d+$`)
	packageNameRegex := regexp.MustCompile(`^([^@=><~]+)(([=><~]+)([^@]+))?(@([a-zA-Z0-9]+))?$`)
	packageNameRegex.Longest()

	if strings.HasPrefix(pkgName, "so:") {
		onlyPkgName, pkgVersion, found := strings.Cut(pkgName, "=")
		if found && !endsWithReleaseStr.MatchString(pkgVersion) {
			pkgName = onlyPkgName + "=0." + pkgVersion
		}
	}

	parts := packageNameRegex.FindAllStringSubmatch(pkgName, -1)
	if len(parts) == 0 || len(parts[0]) < 2 {
		return ParsedConstraint{Name: pkgName, dep: versionAny}
	}
	p := ParsedConstraint{
		Name:    parts[0][1],
		Version: parts[0][4],
		pin:     parts[0][6],
		dep:     versionAny,
	}
	switch parts[0][3] {
	case "=":
		p.dep = versionEqual
	case ">":
		p.dep = versionGreater
	case "<":
		p.dep = versionLess
	case ">=":
		p.dep = versionGreaterEqual
	case "<=":
		p.dep = versionLessEqual
	case "~", "=~":
		p.dep = versionTilde
	}
	return p
}

var resolveCases = []string{
	"",
	"foo",
	"foo=1.2.3-r0",
	"foo>=1.2",
	"foo<=1.2",
	"foo>1",
	"foo<1",
	"foo~1.2",
	"foo=~1.2",
	"foo=1.2.3-r0@wolfi",
	"foo@wolfi",
	"foo@",
	"foo=",
	"foo==",
	"foo===",
	"foo=@wolfi",
	"foo=1@",
	"foo=1@pin-with-dash",
	"foo=1@p@q",
	"foo@p@q",
	"=1.2",
	"@pin",
	"so:libfoo.so.1=1",
	"so:libfoo.so.1=1.2.3-r0",
	"so:libfoo.so.1=1-r",
	"so:libfoo.so.1=1-r5x",
	"so:libfoo.so.1=1@wolfi",
	"so:libfoo.so.1",
	"so:=1",
	"cmd:tool=1.0-r0",
	"pc:libfoo=1.0",
	"cmd:weird@name=1",
	"a=>1",
	"a=<1",
	"a==1",
	"a~=1",
	"a=1=2",
	"a=1>2@pin",
	"héllo=1",
	"a=1@pïn",
	"a>=",
	"a>=@x",
}

// lockPackageNameRegex is the copy pkg/build/lock.go used to carry, without
// the leftmost-longest setting and without the shared library tweak.
var lockPackageNameRegex = regexp.MustCompile(`^([^@=><~]+)(([=><~]+)([^@]+))?(@([a-zA-Z0-9]+))?$`)

func checkAgainstRegex(t *testing.T, in string) {
	t.Helper()
	want := regexResolvePackageNameVersionPin(in)
	if got := ResolvePackageNameVersionPin(in); got != want {
		t.Errorf("ResolvePackageNameVersionPin(%q) = %+v, regex says %+v", in, got, want)
	}
	if got := constraintName(in); got != want.Name {
		t.Errorf("constraintName(%q) = %q, regex says %q", in, got, want.Name)
	}

	parts := lockPackageNameRegex.FindStringSubmatch(in)
	got, ok := ParseConstraint(in)
	if ok != (parts != nil) {
		t.Errorf("ParseConstraint(%q) ok = %v, regex matched = %v", in, ok, parts != nil)
	} else if ok && got.Name != parts[1] {
		t.Errorf("ParseConstraint(%q).Name = %q, regex says %q", in, got.Name, parts[1])
	}
}

func TestResolvePackageNameVersionPinMatchesRegex(t *testing.T) {
	for _, in := range resolveCases {
		checkAgainstRegex(t, in)
	}
}

func FuzzResolvePackageNameVersionPinMatchesRegex(f *testing.F) {
	for _, in := range resolveCases {
		f.Add(in)
	}
	f.Fuzz(checkAgainstRegex)
}
