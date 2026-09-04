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
	"context"
	"maps"
	"slices"
	"strings"
	"sync"

	apkometrics "chainguard.dev/apko/pkg/metrics"
)

// maxResolverCacheEntries bounds the number of distinct index combinations
// each derived cache retains. The live set is tiny (a handful of repos times a
// couple of arches), so the bound only matters for superseded generations
// that in-flight resolutions keep requesting: those age out once nothing asks
// for them anymore.
const maxResolverCacheEntries = 16

// lruCache is a tiny mutex-guarded LRU keyed by the exact []NamedIndex. Index
// objects are immutable and remote generations are deduplicated by (url, etag)
// in globalIndexCache, so comparing the index objects themselves is a complete
// key. The lock is held across lookup and fill so concurrent requests for the
// same combination build it once.
type lruCache[V any] struct {
	sync.Mutex
	max     int
	entries []lruEntry[V] // most recently used first
}

type lruEntry[V any] struct {
	indexes []NamedIndex
	val     V
}

func newLRUCache[V any](size int) *lruCache[V] {
	return &lruCache[V]{max: size}
}

// getOrFill returns the cached value for indexes, computing and inserting it
// on a miss. The boolean reports whether the value was already cached.
func (c *lruCache[V]) getOrFill(indexes []NamedIndex, fill func() V) (V, bool) {
	c.Lock()
	defer c.Unlock()

	for i, e := range c.entries {
		if slices.Equal(e.indexes, indexes) {
			c.entries = slices.Insert(slices.Delete(c.entries, i, i+1), 0, e)
			return e.val, true
		}
	}

	val := fill()
	c.entries = slices.Insert(c.entries, 0, lruEntry[V]{indexes: slices.Clone(indexes), val: val})
	if len(c.entries) > c.max {
		c.entries = c.entries[:c.max:c.max]
	}
	return val, false
}

func (c *lruCache[V]) len() int {
	c.Lock()
	defer c.Unlock()
	return len(c.entries)
}

// It is expensive to parse every version in the APKINDEX and grow a bunch of maps.
// This caches a PkgResolver based on the input []NamedIndex.
var globalResolverCache = &resolverCache{newLRUCache[*PkgResolver](maxResolverCacheEntries)}

type resolverCache struct {
	*lruCache[*PkgResolver]
}

func (r *resolverCache) Get(ctx context.Context, indexes []NamedIndex) *PkgResolver {
	pr, hit := r.getOrFill(indexes, func() *PkgResolver {
		return newPkgResolver(ctx, indexes)
	})
	if hit {
		apkometrics.RecordResolverCacheAccess(apkometrics.CacheResultHit)
	} else {
		apkometrics.RecordResolverCacheAccess(apkometrics.CacheResultMiss)
	}
	return pr.Clone()
}

// It is expensive to compute the difference between every architecture.
// This caches that difference based on the input []NamedIndex for every architecture.
var globalDisqualifyCache = &disqualifyCache{newLRUCache[map[*RepositoryPackage]string](maxResolverCacheEntries)}

type disqualifyCache struct {
	*lruCache[map[*RepositoryPackage]string]
}

func (r *disqualifyCache) Get(ctx context.Context, byArch map[string][]NamedIndex) map[*RepositoryPackage]string {
	indexes := slices.Concat(slices.Collect(maps.Values(byArch))...)
	slices.SortFunc(indexes, func(a, b NamedIndex) int {
		return strings.Compare(a.Name(), b.Name())
	})

	dq, _ := r.getOrFill(indexes, func() map[*RepositoryPackage]string {
		return disqualifyDifference(ctx, byArch)
	})
	return maps.Clone(dq)
}
