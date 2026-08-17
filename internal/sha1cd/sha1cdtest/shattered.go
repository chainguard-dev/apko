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

// Package sha1cdtest provides a real SHA-1 collision, shared by the tests that
// check collision detection actually fires.
//
// This cannot be a shattered_test.go: Go refuses to import a package built only
// from _test.go files ("no non-test Go files"), so a shared fixture has to live
// in an ordinary file. Three things keep it out of production code anyway. It is
// under internal/, so nothing outside apko can reach it. [Shattered] takes a
// [testing.TB], which only a test can supply. And no non-test file imports this
// package, so it is never linked into any apko binary — `go list -deps` over the
// commands does not mention it.
package sha1cdtest

import (
	"encoding/hex"
	"testing"
)

// shattered is the first 320 bytes of shattered-1.pdf, the identical-prefix
// SHA-1 collision published as SHAttered (https://shattered.io). Both halves of
// that collision share these bytes, and they are what the collision detection
// recognises, so hashing them must be refused.
const shattered = "255044462d312e330a25e2e3cfd30a0a0a312030206f626a0a3c3c2f57696474" +
	"682032203020522f4865696768742033203020522f547970652034203020522f" +
	"537562747970652035203020522f46696c7465722036203020522f436f6c6f72" +
	"53706163652037203020522f4c656e6774682038203020522f42697473506572" +
	"436f6d706f6e656e7420383e3e0a73747265616d0affd8fffe00245348412d31" +
	"20697320646561642121212121852fec092339759c39b1a1c63c4c97e1fffe01" +
	"7346dc9166b67e118f029ab621b2560ff9ca67cca8c7f85ba84c79030c2b3de2" +
	"18f86db3a90901d5df45c14f26fedfb3dc38e96ac22fe7bd728f0e45bce046d2" +
	"3c570feb141398bb552ef5a0a82be331fea48037b8b5d71f0e332edf93ac3500" +
	"eb4ddc0decc1a864790c782c76215660dd309791d06bd0af3f98cda4bc4629b1"

// Shattered returns a fresh copy of the colliding bytes. Hashing them with
// chainguard.dev/apko/internal/sha1cd reports sha1cd.ErrCollision.
func Shattered(tb testing.TB) []byte {
	tb.Helper()

	b, err := hex.DecodeString(shattered)
	if err != nil {
		tb.Fatalf("corrupt shattered vector: %v", err)
	}
	if len(b) != 320 {
		tb.Fatalf("shattered vector is %d bytes, want 320", len(b))
	}
	return b
}
