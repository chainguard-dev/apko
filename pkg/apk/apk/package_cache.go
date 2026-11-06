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
	"sync"

	"github.com/hashicorp/golang-lru/v2/simplelru"

	"chainguard.dev/apko/pkg/apk/expandapk"
)

// packageCache is an in-memory, singleflight cache of expanded packages that
// counts its holders.
//
// Each cached APKExpanded owns an open descriptor (the private copy behind
// TarFS), so dropping an entry is not enough to release it. An entry is closed
// once it is out of the cache and nobody holds it: when the last holder
// releases it, or when it is evicted or forgotten while unheld.
type packageCache struct {
	mu  sync.Mutex
	lru *simplelru.LRU[string, *packageEntry]
}

type packageEntry struct {
	load   func() (*expandapk.APKExpanded, error)
	refs   int
	cached bool
	closed bool
}

func newPackageCache(maxEntries int) *packageCache {
	c := &packageCache{}
	c.lru = newLRU(maxEntries, func(_ string, e *packageEntry) {
		// Called with c.mu held, from Add, Remove and Purge.
		e.cached = false
		if e.refs == 0 {
			e.close()
		}
	})
	return c
}

// packageRef is one holder's reference to a cache entry.
type packageRef struct {
	c    *packageCache
	key  string
	e    *packageEntry
	once sync.Once
}

// acquire returns the package for key, calling fn to produce it if no entry
// exists. Concurrent callers for the same key share one call. Errors are not
// cached. hit reports whether the entry already existed.
//
// On success the caller holds a reference and must Release it when done with
// the package.
func (c *packageCache) acquire(key string, fn func() (*expandapk.APKExpanded, error)) (*expandapk.APKExpanded, bool, *packageRef, error) {
	c.mu.Lock()
	e, hit := c.lru.Get(key)
	if !hit {
		e = &packageEntry{load: sync.OnceValues(fn), cached: true}
		c.lru.Add(key, e)
	}
	e.refs++
	c.mu.Unlock()

	ref := &packageRef{c: c, key: key, e: e}
	exp, err := e.load()
	if err != nil {
		ref.Forget()
		ref.Release()
		return nil, hit, nil, err
	}
	return exp, hit, ref, nil
}

// Release drops this reference. Releasing the last reference removes the
// entry from the cache and closes it, so its descriptor is not kept open for
// a later build that may never come. Release is idempotent.
func (r *packageRef) Release() {
	r.once.Do(func() {
		c := r.c
		c.mu.Lock()
		defer c.mu.Unlock()
		if r.e.refs == 1 {
			c.removeLocked(r.key, r.e)
		}
		r.e.refs--
		if r.e.refs == 0 && !r.e.cached {
			r.e.close()
		}
	})
}

// Forget removes the entry from the cache if it is still there. Holders,
// including this one, keep their references.
func (r *packageRef) Forget() {
	r.c.mu.Lock()
	defer r.c.mu.Unlock()
	r.c.removeLocked(r.key, r.e)
}

// Forget removes key from the cache. Holders keep their references.
func (c *packageCache) Forget(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lru.Remove(key)
}

func (c *packageCache) removeLocked(key string, e *packageEntry) {
	if cur, ok := c.lru.Peek(key); ok && cur == e {
		c.lru.Remove(key)
	}
}

// close releases the package's descriptor and temp directory. It is only
// called once refs is zero, by which point every acquirer's load has returned.
func (e *packageEntry) close() {
	if e.closed {
		return
	}
	e.closed = true
	exp, err := e.load()
	if err != nil || exp == nil {
		return
	}
	closeExpanded(exp)
}

// closeExpanded releases everything exp holds open or on disk outside the
// cache: the private copy behind TarFS and its temp directory.
func closeExpanded(exp *expandapk.APKExpanded) {
	if exp.TarFS != nil {
		_ = exp.TarFS.Close()
	}
	_ = exp.Close()
}
