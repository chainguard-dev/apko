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
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"

	"github.com/github/go-spdx/v2/spdxexp"
)

// licenseRefPrefix marks references built from apk database license fields,
// so they cannot collide with a reference an embedded SBOM defines.
const licenseRefPrefix = "LicenseRef-apk-"

// licenseExpression converts an apk license field into a valid SPDX license
// expression. Most fields already are one. Others list licenses separated by
// spaces, use lowercase operators, or name licenses SPDX does not list; those
// names become references whose extracted text is the original name.
func licenseExpression(raw string) (string, []LicensingInfo) {
	raw = strings.TrimSpace(raw)
	switch {
	case raw == "":
		return NOASSERTION, nil
	case isLicenseExpression(raw):
		return raw, nil
	}

	tokens := strings.Fields(strings.NewReplacer("(", " ( ", ")", " ) ").Replace(raw))
	bare := true
	for i, tok := range tokens {
		if op := strings.ToUpper(tok); op == "AND" || op == "OR" || op == "WITH" {
			tokens[i], bare = op, false
		}
	}
	if bare {
		// A list naming every license that applies. One that names no listed
		// license is a single name, such as "Public Domain".
		if !slices.ContainsFunc(tokens, isLicenseExpression) {
			return licenseRef(raw)
		}
		tokens = joinAnd(tokens)
	}

	var refs []LicensingInfo
	for i, tok := range tokens {
		if isExpressionSyntax(tok) || (i > 0 && tokens[i-1] == "WITH") || isLicenseExpression(tok) {
			continue
		}
		id := licenseRefID(tok)
		tokens[i] = id
		if !slices.ContainsFunc(refs, func(r LicensingInfo) bool { return r.LicenseID == id }) {
			refs = append(refs, LicensingInfo{LicenseID: id, ExtractedText: tok})
		}
	}

	expr := strings.NewReplacer("( ", "(", " )", ")").Replace(strings.Join(tokens, " "))
	if !isLicenseExpression(expr) {
		return licenseRef(raw)
	}
	return expr, refs
}

func isLicenseExpression(s string) bool {
	ok, _ := spdxexp.ValidateLicenses([]string{s})
	return ok
}

func isExpressionSyntax(tok string) bool {
	switch tok {
	case "AND", "OR", "WITH", "(", ")":
		return true
	}
	return false
}

func joinAnd(licenses []string) []string {
	out := make([]string, 0, 2*len(licenses)-1)
	for i, l := range licenses {
		if i > 0 {
			out = append(out, "AND")
		}
		out = append(out, l)
	}
	return out
}

// licenseRef describes all of raw as one unlisted license.
func licenseRef(raw string) (string, []LicensingInfo) {
	id := licenseRefID(raw)
	return id, []LicensingInfo{{LicenseID: id, ExtractedText: raw}}
}

// licenseRefID derives a reference ID from name, keeping the characters SPDX
// allows in an ID and hashing a name that has none.
func licenseRefID(name string) string {
	id := strings.Trim(strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-':
			return r
		}
		return '-'
	}, name), "-")
	if id == "" {
		h := sha256.Sum256([]byte(name))
		id = hex.EncodeToString(h[:8])
	}
	return licenseRefPrefix + id
}
