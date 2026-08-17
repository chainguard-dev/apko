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

package sha1cd

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"chainguard.dev/apko/internal/sha1cd/sha1cdtest"
)

// Digests of input with no collision signature must match crypto/sha1, so that
// swapping the implementation does not change any checksum apk cares about.
var golden = map[string]string{
	"":            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
	"abc":         "a9993e364706816aba3e25717850c26c9cd0d89d",
	"hello world": "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed",
}

func TestSumBytesGolden(t *testing.T) {
	for in, want := range golden {
		sum, err := SumBytes([]byte(in))
		if err != nil {
			t.Errorf("SumBytes(%q): %v", in, err)
			continue
		}
		if got := hex.EncodeToString(sum); got != want {
			t.Errorf("SumBytes(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestSumGolden(t *testing.T) {
	for in, want := range golden {
		h := New()
		if _, err := h.Write([]byte(in)); err != nil {
			t.Errorf("Write(%q): %v", in, err)
			continue
		}
		sum, err := Sum(h)
		if err != nil {
			t.Errorf("Sum(%q): %v", in, err)
			continue
		}
		if got := hex.EncodeToString(sum); got != want {
			t.Errorf("Sum(%q) = %s, want %s", in, got, want)
		}
		if len(sum) != Size {
			t.Errorf("Sum(%q) is %d bytes, want %d", in, len(sum), Size)
		}
	}
}

func TestSumBytesCollision(t *testing.T) {
	sum, err := SumBytes(sha1cdtest.Shattered(t))
	if !errors.Is(err, ErrCollision) {
		t.Errorf("SumBytes(shattered) = %x, %v; want ErrCollision", sum, err)
	}
	if sum != nil {
		t.Errorf("SumBytes(shattered) returned a digest %x alongside the error", sum)
	}
}

// The collision is only detectable once the digest is finalised, so check that
// it is caught however the input was fed in.
func TestSumCollision(t *testing.T) {
	data := sha1cdtest.Shattered(t)

	for _, chunk := range []int{1, 7, 64, 320} {
		h := New()
		for i := 0; i < len(data); i += chunk {
			if _, err := h.Write(data[i:min(i+chunk, len(data))]); err != nil {
				t.Fatalf("chunk %d: write: %v", chunk, err)
			}
		}
		sum, err := Sum(h)
		if !errors.Is(err, ErrCollision) {
			t.Errorf("chunk %d: Sum = %x, %v; want ErrCollision", chunk, sum, err)
		}
		if sum != nil {
			t.Errorf("chunk %d: Sum returned a digest %x alongside the error", chunk, sum)
		}
	}
}

// Sum also finalises hashes that cannot detect collisions, so callers choosing a
// digest algorithm at runtime have a single finalisation path.
func TestSumPassesThroughOtherHashes(t *testing.T) {
	h := sha256.New()
	if _, err := h.Write([]byte("hello world")); err != nil {
		t.Fatal(err)
	}
	sum, err := Sum(h)
	if err != nil {
		t.Fatalf("Sum(sha256): %v", err)
	}
	const want = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	if got := hex.EncodeToString(sum); got != want {
		t.Errorf("Sum(sha256) = %s, want %s", got, want)
	}
}
