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

package apk

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Sanitize archive file pathing from "G305: Zip Slip vulnerability"
func sanitizeArchivePath(d, t string) (v string, err error) {
	v = filepath.Join(d, t)

	// top level content have a directory of "". filepath.Clean("") returns .
	if d == "" || strings.HasPrefix(v, filepath.Clean(d)) {
		return v, nil
	}

	return "", fmt.Errorf("%s: %s", "content filepath is tainted", t)
}

// containsControlCharacter reports whether s contains a byte below 0x20 or the
// DEL byte 0x7f.
//
// Such bytes are rejected in archive entry names because the apk installed
// database is a newline-delimited "<token>:<value>" format written from those
// names verbatim (see AddInstalledPackage). A newline in an entry name lets a
// package terminate the current record and forge additional package entries,
// which then propagate into the generated SBOM.
//
// This mirrors contains_control_character() in apk-tools src/database.c
// (c1594f60, corrected in ab7b8e3 to compare unsigned bytes). Go's byte is
// unsigned, so the comparison below is right by construction, and multi-byte
// UTF-8 is safe: no byte of a multi-byte sequence falls in either range.
//
// unicode.IsControl is deliberately not used: it also reports the C1 range
// U+0080-U+009F, which apk-tools permits, so it would diverge from upstream.
func containsControlCharacter(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}
