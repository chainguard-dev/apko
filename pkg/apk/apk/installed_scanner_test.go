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
	"bufio"
	"errors"
	"strings"
	"testing"
)

// A record line longer than the scanner's buffer stops the scan. Until this was
// checked, ParseInstalled returned the packages accumulated so far together with
// a nil error, so a single over-long line silently erased every package after it
// -- and, when the offending line was in the first record, all of them.
//
// That is the concealment impact of GHSA-389p-892w-qwgf reached without any
// control character: pkg/build/sbom.go derives the SBOM from GetInstalled(), and
// isInstalledPackage() concurrently reports every package as not installed. The
// truncation has to be an error, not a shorter answer.
func TestParseInstalledRejectsOverlongLines(t *testing.T) {
	record := func(name, extra string) string {
		return "P:" + name + "\nV:1.0\nA:x86_64\n" + extra + "\n"
	}

	cases := []struct {
		name string
		// pad is the length of the oversized dependency value.
		pad        int
		wantReject bool
	}{
		{name: "line within the raised bound", pad: 1 << 16, wantReject: false},
		{name: "line at eight times the default bound", pad: 8 << 16, wantReject: false},
		{name: "line beyond the raised bound", pad: maxInstalledLineLen + 1, wantReject: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := record("first", "D:"+strings.Repeat("a", tc.pad)) + "\n" +
				record("second", "D:libc") + "\n" +
				record("third", "D:libc") + "\n"

			pkgs, err := ParseInstalled(strings.NewReader(db))

			if tc.wantReject {
				if err == nil {
					t.Fatalf("ParseInstalled = nil error with %d packages; an over-long line "+
						"must be an error, not a truncated package list", len(pkgs))
				}
				if !errors.Is(err, bufio.ErrTooLong) {
					t.Errorf("error = %v, want it to wrap bufio.ErrTooLong so a caller can tell "+
						"a malformed database from an I/O failure", err)
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseInstalled = %v, want acceptance: a long dependency list is "+
					"legitimate and previously parsed", err)
			}
			// The point of raising the bound is that the packages after the long
			// line survive. Asserting only on err would pass if the scan stopped.
			if len(pkgs) != 3 {
				got := make([]string, 0, len(pkgs))
				for _, p := range pkgs {
					got = append(got, p.Name)
				}
				t.Errorf("parsed %d packages (%v), want 3; the records after the long line "+
					"were dropped", len(pkgs), got)
			}
		})
	}
}

// An R: value that escapes its F: directory used to be silently converted into a
// file header with an empty Name, because ParseInstalled discarded
// sanitizeArchivePath's error. pkg/build feeds those headers straight back into
// AddInstalledPackage when the image is used as a base, so the traversal became
// an unexplained failure -- or, before the guards existed, a junk "R:." line.
//
// apk-tools refuses ".." in an entry name outright and nothing legitimate
// produces one, so this is an error rather than something to tolerate.
func TestParseInstalledRejectsTraversalInFileRecords(t *testing.T) {
	cases := []struct {
		name       string
		db         string
		wantReject bool
	}{
		{
			name: "file inside its directory",
			db:   "P:p\nV:1.0\nA:x86_64\nF:usr/bin\nR:tool\n\n",
		},
		{
			name:       "file escaping its directory",
			db:         "P:p\nV:1.0\nA:x86_64\nF:usr/bin\nR:../../evil\n",
			wantReject: true,
		},
		{
			name:       "file escaping to an absolute-looking path",
			db:         "P:p\nV:1.0\nA:x86_64\nF:usr/bin\nR:../../../etc/shadow\n",
			wantReject: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkgs, err := ParseInstalled(strings.NewReader(tc.db))

			if tc.wantReject {
				if err == nil {
					t.Fatalf("ParseInstalled = nil error; a traversal must be refused, not "+
						"turned into an empty file name. parsed = %+v", pkgs)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseInstalled = %v, want acceptance", err)
			}
			if len(pkgs) != 1 {
				t.Fatalf("parsed %d packages, want 1", len(pkgs))
			}
			// Guard against the empty-Name regression specifically: an entry
			// whose name is "" is the shape that used to escape.
			for _, f := range pkgs[0].Files {
				if f.Name == "" {
					t.Errorf("file header has an empty Name; files = %+v", pkgs[0].Files)
				}
			}
		})
	}
}
