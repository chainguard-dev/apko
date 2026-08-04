package apk

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestSupersededGenerationsAreCollectable guards against derived resolution
// data (resolvers, disqualify sets) pinning superseded index generations.
// Every etag rotation used to leak the entire previous generation via the
// global resolver and disqualify caches; replacing a generation now purges
// its derived entries, and resolutions still holding a superseded generation
// (as concurrent builds do when an index rotates mid-flight) must not
// re-insert it.
func TestSupersededGenerationsAreCollectable(t *testing.T) {
	const nPkgs = 10000

	idx := &APKIndex{Description: "leak-test"}
	for i := range nPkgs {
		idx.Packages = append(idx.Packages, &Package{
			Name:        fmt.Sprintf("pkg-%d", i),
			Version:     "1.0.0-r0",
			Arch:        "x86_64",
			Description: fmt.Sprintf("synthetic package %d", i),
			Checksum:    []byte("01234567890123456789"),
			// A short chain keeps the resolve cheap; the index stays large.
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
	defer srv.Close()

	ctx := context.Background()
	heapMB := func() float64 {
		runtime.GC()
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return float64(m.HeapAlloc) / (1 << 20)
	}

	resolve := func(indexes []NamedIndex) {
		p := NewPkgResolver(ctx, indexes)
		// Two arches so the disqualify cache is exercised too.
		if _, _, err := p.GetPackagesWithDependencies(ctx, []string{"pkg-0"},
			map[string][]NamedIndex{"x86_64": indexes, "aarch64": indexes}); err != nil {
			t.Fatal(err)
		}
	}

	fetch := func(g int) []NamedIndex {
		etag.Store(fmt.Sprintf("gen-%d", g))
		indexes, err := GetRepositoryIndexes(ctx, []string{srv.URL}, nil, "x86_64",
			WithIgnoreSignatures(true), WithHTTPClient(srv.Client()))
		if err != nil {
			t.Fatal(err)
		}
		return indexes
	}

	// Warm up allocator and caches, then measure growth across generations.
	resolve(fetch(0))
	base := heapMB()
	const generations = 8
	prev := fetch(1)
	for g := 2; g <= generations+1; g++ {
		// Fetching generation g evicts generation g-1, which an unfinished
		// resolution still holds — like a build racing an index rotation.
		// Resolving with it afterwards must not re-pin it.
		indexes := fetch(g)
		resolve(prev)
		resolve(indexes)
		prev = indexes
	}
	prev = nil
	_ = prev
	grown := heapMB() - base

	// Each pinned generation retains several MB (index, resolver maps,
	// disqualify sets). With correct purging, growth stays near zero; the
	// unpurged caches grew by roughly generations * per-generation size
	// (tens of MB here).
	if grown > 20 {
		t.Errorf("heap grew by %.1f MB across %d index generations, derived data is likely pinned", grown, generations)
	}
}

// TestSupersededGenerationsConcurrentlyBounded drives index rotations and
// resolutions concurrently, so a purge genuinely races an in-flight Get that
// still holds a superseded generation - the case the insert gate exists for
// and the sequential test above does not reach. It asserts the resolver cache
// retains only a bounded number of generations for the URL rather than one
// per rotation. Run under -race to also catch data races and deadlocks.
func TestSupersededGenerationsConcurrentlyBounded(t *testing.T) {
	const nPkgs = 300

	idx := &APKIndex{Description: "concurrent-leak-test"}
	for i := range nPkgs {
		idx.Packages = append(idx.Packages, &Package{
			Name:         fmt.Sprintf("pkg-%d", i),
			Version:      "1.0.0-r0",
			Arch:         "x86_64",
			Checksum:     []byte("01234567890123456789"),
			Dependencies: []string{fmt.Sprintf("pkg-%d", min(i+1, 20))},
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

	// ETag tracks a counter the workers bump; each distinct value the HEAD
	// observes is a new generation of the same URL.
	var gen atomic.Int64
	gen.Store(1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", fmt.Sprintf("%q", fmt.Sprintf("gen-%d", gen.Load())))
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(body.Bytes())
	}))
	defer srv.Close()

	ctx := t.Context()
	const (
		workers = 4
		rounds  = 60
	)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for range rounds {
				gen.Add(1) // rotate: a new generation supersedes the current one
				indexes, err := GetRepositoryIndexes(ctx, []string{srv.URL}, nil, "x86_64",
					WithIgnoreSignatures(true), WithHTTPClient(srv.Client()))
				if err != nil {
					t.Errorf("fetch: %v", err)
					return
				}
				// Populates globalResolverCache for the current generation, or
				// takes the gate's uncached path if this index was superseded
				// by a concurrent rotation in the meantime.
				_ = NewPkgResolver(ctx, indexes)
			}
		})
	}
	wg.Wait()

	// The workers drove workers*rounds rotations. Without eviction the resolver
	// cache would hold ~that many generations for the URL; with it, only the
	// current generation and a few racing stragglers survive.
	url := IndexURL(srv.URL, "x86_64")
	if got := countResolverGenerations(url); got > 20 {
		t.Errorf("resolver cache retains %d generations for %s; superseded generations are not being evicted (expected a small bound)", got, url)
	}
}

// countResolverGenerations counts the distinct index generations the global
// resolver cache still holds for a single index URL (one top-level trie child
// per generation, since these resolvers are built from a single index).
func countResolverGenerations(url string) int {
	globalResolverCache.Lock()
	defer globalResolverCache.Unlock()

	n := 0
	for k := range globalResolverCache.children {
		if k.Source() == url {
			n++
		}
	}
	return n
}
