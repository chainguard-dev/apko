package apk

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

const testRSA256KeyName = "test-rsa256.rsa.pub"

// signedIndexFixture returns the bytes of the rsa256-signed test index and
// the keyring that verifies it.
func signedIndexFixture(t *testing.T) (index []byte, keys map[string][]byte) {
	t.Helper()
	index, err := os.ReadFile(filepath.Join(testRSA256IndexPkgDir, "APKINDEX.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(filepath.Join(testRSA256IndexPkgDir, testRSA256KeyName))
	if err != nil {
		t.Fatal(err)
	}
	return index, map[string][]byte{testRSA256KeyName: key}
}

// localSignedRepo writes the signed test index into a fresh local
// repository and returns its path.
func localSignedRepo(t *testing.T, index []byte) string {
	t.Helper()
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, testArch), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, testArch, "APKINDEX.tar.gz"), index, 0o644); err != nil {
		t.Fatal(err)
	}
	return repo
}

// remoteSignedRepo serves the signed test index with a fixed etag, so every
// request is the same cached generation, and returns the repository URL.
func remoteSignedRepo(t *testing.T, index []byte) (string, *http.Client) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"fixed"`)
		_, _ = w.Write(index)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, srv.Client()
}

// TestIndexCacheHonorsVerification pins that the parsed-index cache never
// serves an index to a caller who would reject it: not after the key that
// verified it is removed, and not to a caller that checks signatures after
// one that did not.
func TestIndexCacheHonorsVerification(t *testing.T) {
	index, keys := signedIndexFixture(t)

	for _, tc := range []struct {
		name string
		repo func(t *testing.T) (string, []IndexOption)
	}{{
		name: "local",
		repo: func(t *testing.T) (string, []IndexOption) {
			return localSignedRepo(t, index), nil
		},
	}, {
		name: "remote",
		repo: func(t *testing.T) (string, []IndexOption) {
			u, client := remoteSignedRepo(t, index)
			return u, []IndexOption{WithHTTPClient(client)}
		},
	}} {
		t.Run(tc.name+"/key removed", func(t *testing.T) {
			repo, opts := tc.repo(t)
			if _, err := GetRepositoryIndexes(t.Context(), []string{repo}, keys, testArch, opts...); err != nil {
				t.Fatalf("GetRepositoryIndexes(with key): got err = %v, want nil", err)
			}
			other := map[string][]byte{"other.rsa.pub": keys[testRSA256KeyName]}
			if _, err := GetRepositoryIndexes(t.Context(), []string{repo}, other, testArch, opts...); err == nil {
				t.Error("GetRepositoryIndexes(verifying key removed): got err = nil, want a signature error")
			}
		})

		t.Run(tc.name+"/unverified then verified", func(t *testing.T) {
			repo, opts := tc.repo(t)
			unverified := append([]IndexOption{WithIgnoreSignatures(true)}, opts...)
			if _, err := GetRepositoryIndexes(t.Context(), []string{repo}, nil, testArch, unverified...); err != nil {
				t.Fatalf("GetRepositoryIndexes(ignoring signatures): got err = %v, want nil", err)
			}
			if _, err := GetRepositoryIndexes(t.Context(), []string{repo}, nil, testArch, opts...); err == nil {
				t.Error("GetRepositoryIndexes(verifying, no keys) after an unverified parse: got err = nil, want an error")
			}
		})

		t.Run(tc.name+"/same keys reuse the parse", func(t *testing.T) {
			repo, opts := tc.repo(t)
			first, err := GetRepositoryIndexes(t.Context(), []string{repo}, keys, testArch, opts...)
			if err != nil {
				t.Fatalf("GetRepositoryIndexes: got err = %v, want nil", err)
			}
			// A fresh map holding the same keys is the same trust.
			same := map[string][]byte{testRSA256KeyName: append([]byte{}, keys[testRSA256KeyName]...)}
			second, err := GetRepositoryIndexes(t.Context(), []string{repo}, same, testArch, opts...)
			if err != nil {
				t.Fatalf("GetRepositoryIndexes(same keys): got err = %v, want nil", err)
			}
			if first[0] != second[0] {
				t.Error("GetRepositoryIndexes(same keys): got a fresh parse, want the cached index")
			}
		})
	}
}
