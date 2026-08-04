package apk

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"weak"
)

func internTestIndexBody(t *testing.T, nPkgs int) []byte {
	t.Helper()
	idx := &APKIndex{Description: "intern-test"}
	for i := range nPkgs {
		idx.Packages = append(idx.Packages, &Package{
			Name:    fmt.Sprintf("pkg-%d", i),
			Version: "1.0.0-r0",
			Arch:    "x86_64",
			// A fat payload so sharing dominates the heap measurements.
			Description:  strings.Repeat(fmt.Sprintf("synthetic package %d ", i), 50),
			Checksum:     fmt.Appendf(nil, "checksum-of-pkg-%05d", i),
			Dependencies: []string{fmt.Sprintf("pkg-%d", min(i+1, 20))},
			Provides:     []string{fmt.Sprintf("cmd:tool-%d=1.0.0-r0", i)},
			BuildTime:    time.Unix(1700000000, 0).UTC(),
		})
	}
	archive, err := ArchiveFromIndex(idx)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(archive)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func internTestServer(t *testing.T, body []byte) *httptest.Server {
	t.Helper()
	var etag atomic.Value
	etag.Store("gen-0")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", fmt.Sprintf("%q", r.URL.Query().Get("gen")+"gen"))
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// Indexes at different URLs carrying the same packages must share the parsed
// Package payloads.
func TestInterningSharesPackagesAcrossIndexes(t *testing.T) {
	ctx := t.Context()
	body := internTestIndexBody(t, 100)
	srv := internTestServer(t, body)

	fetch := func(repo string) NamedIndex {
		indexes, err := GetRepositoryIndexes(ctx, []string{repo}, nil, "x86_64",
			WithIgnoreSignatures(true), WithHTTPClient(srv.Client()))
		if err != nil {
			t.Fatal(err)
		}
		return indexes[0]
	}

	a := fetch(srv.URL + "/repo-a")
	b := fetch(srv.URL + "/repo-b")

	for i, pkg := range a.Packages() {
		if pkg.Package != b.Packages()[i].Package {
			t.Fatalf("package %d not shared across indexes", i)
		}
	}
}

// Records that differ in any field must not be conflated, even when they share
// a name and control hash. Dependencies is a field the old six-field guard did
// not compare; DeepEqual does, which is what keeps interning safe across
// repository trust boundaries.
func TestInterningRejectsMismatchedRecords(t *testing.T) {
	a := &Package{Name: "pkg", Version: "1.0.0-r0", Checksum: []byte("intern-mismatch-test"), Dependencies: []string{"honest-dep"}}
	b := &Package{Name: "pkg", Version: "1.0.0-r0", Checksum: []byte("intern-mismatch-test"), Dependencies: []string{"honest-dep", "evil-dep"}}

	canonical := internPackage(a)
	if canonical != a {
		t.Fatal("first package should become canonical")
	}
	// b shares a's name and checksum but differs, so it must not be conflated
	// with the canonical. Comparing against canonical also keeps a live across
	// this call, so the mismatch path is exercised rather than a dead-entry miss.
	if internPackage(b) == canonical {
		t.Fatal("record differing only in dependencies was conflated")
	}
}

// The intern table holds packages weakly, so an interned package must be
// collectable once no live index references it; a strong table would pin it
// forever. (The dead map entry lingers until overwritten, which is intended.)
func TestInterningDoesNotPinPackages(t *testing.T) {
	var observer weak.Pointer[Package]
	func() {
		pkg := internPackage(&Package{
			Name:     "collectable",
			Version:  "1.0.0-r0",
			Checksum: []byte("intern-collect-test"),
		})
		observer = weak.Make(pkg)
	}()

	deadline := time.Now().Add(10 * time.Second)
	for observer.Value() != nil {
		if time.Now().After(deadline) {
			t.Fatal("interned package was not collected; the table is pinning it")
		}
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
	}
}

// Loading identical indexes from distinct URLs must share package objects, not
// duplicate them: the union of every index's package pointers is one index's
// worth, not one per index.
func TestInterningDeduplicatesAcrossURLs(t *testing.T) {
	const nPkgs = 1000
	const copies = 4

	ctx := t.Context()
	body := internTestIndexBody(t, nPkgs)
	srv := internTestServer(t, body)

	seen := map[*Package]struct{}{}
	for i := range copies {
		got, err := GetRepositoryIndexes(ctx, []string{fmt.Sprintf("%s/repo-%d", srv.URL, i)}, nil, "x86_64",
			WithIgnoreSignatures(true), WithHTTPClient(srv.Client()))
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range got[0].Packages() {
			seen[p.Package] = struct{}{}
		}
	}

	if len(seen) != nPkgs {
		t.Errorf("saw %d distinct package objects across %d identical indexes, want %d", len(seen), copies, nPkgs)
	}
}
