package apk

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"chainguard.dev/apko/pkg/apk/auth"
)

// TestAuthenticatorDoesNotMemoize pins the property the race fix depends on:
// resolving the default authenticator must not write it back into the
// indexOpts that GetRepositoryIndexes shares across its per-repository
// goroutines.
func TestAuthenticatorDoesNotMemoize(t *testing.T) {
	opts := &indexOpts{}
	// DefaultAuthenticators holds a slice type, which == would panic on.
	if got := opts.authenticator(); !reflect.DeepEqual(got, auth.DefaultAuthenticators) {
		t.Errorf("authenticator() = %v, want auth.DefaultAuthenticators", got)
	}
	if opts.auth != nil {
		t.Error("authenticator() wrote the default back into indexOpts")
	}

	want := auth.StaticAuth("", "user", "pass")
	opts = &indexOpts{auth: want}
	if got := opts.authenticator(); got != want {
		t.Errorf("authenticator() = %v, want the configured authenticator", got)
	}
}

// TestGetRepositoryIndexesAnonymousConcurrent fetches several repositories
// with no authenticator configured, which is what makes the shared indexOpts
// interesting: every per-repository goroutine used to resolve the default
// authenticator by writing to it. Fails under -race before the fix.
func TestGetRepositoryIndexesAnonymousConcurrent(t *testing.T) {
	idx := &APKIndex{Description: "auth-race-test"}
	for i := range 4 {
		idx.Packages = append(idx.Packages, &Package{
			Name:     fmt.Sprintf("pkg-%d", i),
			Version:  "1.0.0-r0",
			Arch:     "x86_64",
			Checksum: []byte("01234567890123456789"),
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

	// No ETag: the fetch is not deduplicated, so every repository runs the
	// full HEAD-then-GET path, each of which authenticates its request.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(body.Bytes())
	}))
	defer srv.Close()

	repos := make([]string, 0, 8)
	for i := range cap(repos) {
		repos = append(repos, fmt.Sprintf("%s/repo-%d", srv.URL, i))
	}

	indexes, err := GetRepositoryIndexes(t.Context(), repos, nil, "x86_64",
		WithIgnoreSignatures(true), WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	if len(indexes) != len(repos) {
		t.Errorf("got %d indexes, want %d", len(indexes), len(repos))
	}
}
