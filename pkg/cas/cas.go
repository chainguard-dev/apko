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

// Package cas provides content-addressed stores for file contents.
package cas

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
)

// Digest is the sha256 of a blob's contents.
type Digest [sha256.Size]byte

// Empty is the digest of the empty blob.
var Empty = Of(nil)

// Of returns the digest of b.
func Of(b []byte) Digest {
	return sha256.Sum256(b)
}

// String renders d as "sha256:<hex>".
func (d Digest) String() string {
	return "sha256:" + hex.EncodeToString(d[:])
}

// ParseDigest parses the "sha256:<hex>" form produced by [Digest.String].
func ParseDigest(s string) (Digest, error) {
	var d Digest
	hexsum, ok := strings.CutPrefix(s, "sha256:")
	if !ok {
		return d, fmt.Errorf("digest %q: missing sha256: prefix", s)
	}
	b, err := hex.DecodeString(hexsum)
	if err != nil {
		return d, fmt.Errorf("digest %q: %w", s, err)
	}
	if len(b) != len(d) {
		return d, fmt.Errorf("digest %q: want %d bytes, got %d", s, len(d), len(b))
	}
	copy(d[:], b)
	return d, nil
}

// ErrNotFound is returned by [Store.OpenBlob] for a digest the store does not hold.
var ErrNotFound = errors.New("blob not found")

// Store serves blobs by digest.
//
// The returned reader is fresh for each call, so concurrent readers of the
// same blob do not share a position.
type Store interface {
	OpenBlob(d Digest) (*io.SectionReader, error)
}

func emptyBlob() *io.SectionReader {
	return io.NewSectionReader(bytes.NewReader(nil), 0, 0)
}

// Memory is an in-memory [Store].
type Memory struct {
	mu    sync.RWMutex
	blobs map[Digest][]byte
}

func NewMemory() *Memory {
	return &Memory{blobs: map[Digest][]byte{}}
}

// Put stores b and returns its digest. The store takes ownership of b.
func (m *Memory) Put(b []byte) Digest {
	d := Of(b)
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.blobs[d]; !ok {
		m.blobs[d] = b
	}
	return d
}

func (m *Memory) OpenBlob(d Digest) (*io.SectionReader, error) {
	if d == Empty {
		return emptyBlob(), nil
	}
	m.mu.RLock()
	b, ok := m.blobs[d]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%s: %w", d, ErrNotFound)
	}
	return io.NewSectionReader(bytes.NewReader(b), 0, int64(len(b))), nil
}

// Union routes each digest to its registered [Store].
type Union struct {
	mu     sync.RWMutex
	routes map[Digest]Store
}

func NewUnion() *Union {
	return &Union{routes: map[Digest]Store{}}
}

// Add registers s for d, keeping the existing store if d is already registered.
func (u *Union) Add(d Digest, s Store) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if _, ok := u.routes[d]; !ok {
		u.routes[d] = s
	}
}

func (u *Union) OpenBlob(d Digest) (*io.SectionReader, error) {
	if d == Empty {
		return emptyBlob(), nil
	}
	u.mu.RLock()
	s, ok := u.routes[d]
	u.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%s: %w", d, ErrNotFound)
	}
	return s.OpenBlob(d)
}
