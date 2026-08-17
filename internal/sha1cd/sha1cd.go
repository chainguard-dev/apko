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

// Package sha1cd computes SHA-1 digests with collision detection.
//
// apk identifies control sections, signatures and individual files by SHA-1,
// and signs legacy indexes over SHA-1, so we cannot stop computing it. What we
// can do is refuse to trust a digest computed over input that carries the
// cryptanalytic signature of a SHA-1 collision attack. Callers finalise a hash
// with [Sum], which runs that check and reports [ErrCollision] instead of
// returning a digest that must not be used.
//
// For input with no collision signature the digests are identical to
// crypto/sha1, so this is a drop-in replacement. For input that does collide
// the digest differs (the underlying implementation rehashes to a safe value),
// which is a second reason never to use a digest without checking first.
package sha1cd

import (
	"errors"
	"hash"

	upstream "github.com/pjbgf/sha1cd"
)

// Size is the length in bytes of a SHA-1 digest.
const Size = upstream.Size

// ErrCollision reports that the hashed input exhibits the characteristics of a
// SHA-1 collision attack, so its digest cannot be trusted to identify content.
var ErrCollision = errors.New("sha1 collision attack detected in hashed input")

// New returns a [hash.Hash] computing SHA-1 with collision detection.
//
// Finalise it with [Sum] rather than its own Sum method: collision detection is
// only conclusive once the digest is finalised, and Sum is what checks it.
func New() hash.Hash {
	return upstream.New()
}

// Sum finalises h and returns its digest.
//
// When h came from [New], the digest is checked before it is returned and
// ErrCollision is reported instead if the input collides.
//
// A hash that cannot detect collisions, such as sha256, is simply finalised.
// That passthrough is for callers holding a hash.Hash whose algorithm is only
// known at runtime, so that whichever hash they end up with is checked if it is
// SHA-1. Where the algorithm is known at the call site, call [SumBytes] or that
// digest's own package instead, so the code does not read as though SHA-1 were
// involved when it is not.
func Sum(h hash.Hash) ([]byte, error) {
	crh, ok := h.(upstream.CollisionResistantHash)
	if !ok {
		return h.Sum(nil), nil
	}
	sum, collision := crh.CollisionResistantSum(nil)
	if collision {
		return nil, ErrCollision
	}
	return sum, nil
}

// SumBytes returns the SHA-1 of data, or ErrCollision if data exhibits the
// characteristics of a SHA-1 collision attack.
func SumBytes(data []byte) ([]byte, error) {
	sum, collision := upstream.Sum(data)
	if collision {
		return nil, ErrCollision
	}
	return sum[:], nil
}
