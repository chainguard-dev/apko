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
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// rotatingIndexServer serves a synthetic APKINDEX whose etag is controlled
// by the returned setter. Every distinct etag is a new generation of the
// same URL.
func rotatingIndexServer(t *testing.T, nPkgs int) (*httptest.Server, func(gen int)) {
	t.Helper()

	idx := &APKIndex{Description: "rotation-test"}
	for i := range nPkgs {
		idx.Packages = append(idx.Packages, &Package{
			Name:         fmt.Sprintf("pkg-%d", i),
			Version:      "1.0.0-r0",
			Arch:         "x86_64",
			Description:  fmt.Sprintf("synthetic package %d", i),
			Checksum:     []byte("01234567890123456789"),
			Dependencies: []string{fmt.Sprintf("pkg-%d", min(i+1, 20))},
			Provides:     []string{fmt.Sprintf("cmd:tool-%d=1.0.0-r0", i)},
			BuildTime:    time.Unix(1700000000, 0).UTC(),
		})
	}
	archive, err := ArchiveFromIndex(idx)
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	if _, err := body.ReadFrom(archive); err != nil {
		t.Fatal(err)
	}

	var etag atomic.Value
	etag.Store("gen-0")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", fmt.Sprintf("%q", etag.Load()))
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(body.Bytes())
	}))
	t.Cleanup(srv.Close)

	return srv, func(gen int) { etag.Store(fmt.Sprintf("gen-%d", gen)) }
}

func fetchIndexes(t *testing.T, ctx context.Context, srv *httptest.Server) []NamedIndex {
	t.Helper()
	indexes, err := GetRepositoryIndexes(ctx, []string{srv.URL}, nil, "x86_64",
		WithIgnoreSignatures(true), WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	return indexes
}

func resolveWith(t *testing.T, ctx context.Context, indexes []NamedIndex) *PkgResolver {
	t.Helper()
	p := NewPkgResolver(ctx, indexes)
	// Two arches so the disqualify cache is exercised too.
	if _, _, err := p.GetPackagesWithDependencies(ctx, []string{"pkg-0"},
		map[string][]NamedIndex{"x86_64": indexes, "aarch64": indexes}); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestSupersededIndexStillServedFromCache guards against the cache refusing
// to serve resolvers for an index set that is no longer the freshest
// generation. Concurrent builds routinely hold an index generation that a
// sibling has since superseded, and a resolver built over a specific set of
// index objects is correct for that set regardless of what has been fetched
// since. Bypassing the cache there rebuilt the resolver on nearly every call.
func TestSupersededIndexStillServedFromCache(t *testing.T) {
	srv, rotate := rotatingIndexServer(t, 300)
	ctx := t.Context()

	rotate(1)
	stale := fetchIndexes(t, ctx, srv)
	rotate(2)
	fresh := fetchIndexes(t, ctx, srv)
	if stale[0] == fresh[0] {
		t.Fatal("expected the rotation to produce a new index object")
	}

	first := resolveWith(t, ctx, stale)
	n := globalResolverCache.len()
	second := resolveWith(t, ctx, stale)

	if globalResolverCache.len() != n {
		t.Errorf("resolver cache grew from %d to %d entries on a repeated resolve over the same indexes", n, globalResolverCache.len())
	}
	if reflect.ValueOf(first.nameMap).Pointer() != reflect.ValueOf(second.nameMap).Pointer() {
		t.Error("repeated resolve over a superseded index set rebuilt the resolver instead of reusing the cached one")
	}
}

// TestDisqualifyCacheKeyIsOrderIndependent checks that the same multi-arch
// request always maps to a single disqualify entry. The key used to be sorted
// by repository name, which is empty for unpinned repositories, so the order
// fell back to map iteration order and one request could occupy several slots.
func TestDisqualifyCacheKeyIsOrderIndependent(t *testing.T) {
	srv, rotate := rotatingIndexServer(t, 50)
	ctx := t.Context()

	rotate(1)
	a := fetchIndexes(t, ctx, srv)
	rotate(2)
	b := fetchIndexes(t, ctx, srv)

	before := globalDisqualifyCache.len()
	for range 50 {
		globalDisqualifyCache.Get(ctx, map[string][]NamedIndex{"x86_64": a, "aarch64": b})
	}
	if added := globalDisqualifyCache.len() - before; added != 1 {
		t.Errorf("repeated identical disqualify requests added %d entries, want 1", added)
	}
}

// TestSupersededGenerationsAreBounded rotates the index many more times than
// the caches can hold and checks that both derived caches stay at their cap
// and that heap use stops growing once the cap is reached, so superseded
// generations are not pinned indefinitely.
func TestSupersededGenerationsAreBounded(t *testing.T) {
	srv, rotate := rotatingIndexServer(t, 10000)
	ctx := context.Background()

	heapMB := func() float64 {
		runtime.GC()
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return float64(m.HeapAlloc) / (1 << 20)
	}

	gen := 0
	next := func() {
		gen++
		rotate(gen)
		resolveWith(t, ctx, fetchIndexes(t, ctx, srv))
	}

	// Fill both caches to their cap, then measure growth beyond it.
	for range maxResolverCacheEntries {
		next()
	}
	base := heapMB()
	const extra = 2 * maxResolverCacheEntries
	for range extra {
		next()
	}
	grown := heapMB() - base

	if got := globalResolverCache.len(); got > maxResolverCacheEntries {
		t.Errorf("resolver cache holds %d entries, want at most %d", got, maxResolverCacheEntries)
	}
	if got := globalDisqualifyCache.len(); got > maxResolverCacheEntries {
		t.Errorf("disqualify cache holds %d entries, want at most %d", got, maxResolverCacheEntries)
	}
	// Each pinned generation retains several MB (index, resolver maps,
	// disqualify sets). Once the LRU is full, further rotations must not add
	// to the heap beyond allocator noise.
	if grown > 20 {
		t.Errorf("heap grew by %.1f MB across %d rotations past the cache cap, superseded generations are likely pinned", grown, extra)
	}
}

// TestSupersededGenerationsConcurrentlyBounded drives index rotations and
// resolutions concurrently so that resolutions holding superseded
// generations race fresh fetches. The resolver cache must stay bounded rather
// than accumulating one entry per rotation. Run under -race to also catch
// data races and deadlocks.
func TestSupersededGenerationsConcurrentlyBounded(t *testing.T) {
	srv, rotate := rotatingIndexServer(t, 300)
	ctx := t.Context()

	var gen atomic.Int64
	const (
		workers = 4
		rounds  = 60
	)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for range rounds {
				rotate(int(gen.Add(1)))
				indexes, err := GetRepositoryIndexes(ctx, []string{srv.URL}, nil, "x86_64",
					WithIgnoreSignatures(true), WithHTTPClient(srv.Client()))
				if err != nil {
					t.Errorf("fetch: %v", err)
					return
				}
				_ = NewPkgResolver(ctx, indexes)
			}
		})
	}
	wg.Wait()

	if got := globalResolverCache.len(); got > maxResolverCacheEntries {
		t.Errorf("resolver cache holds %d entries after %d rotations, want at most %d", got, workers*rounds, maxResolverCacheEntries)
	}
}
