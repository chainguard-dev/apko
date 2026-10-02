package apk

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/apk/auth"
	"chainguard.dev/apko/pkg/apk/expandapk"
)

// TestCachePackage_RetriesVanishedEntry pins the retry in cachePackage for the
// shared-cache race: a concurrent cachePackage for the same package re-points
// the entry's symlink and unlinks the previous target, and an open() that
// resolved the symlink just before the swap fails, with ENOENT on Linux and
// EINVAL on darwin, on a path that resolves fine again immediately. The
// interleaving needs an unlink to land inside a concurrent open()'s kernel
// path walk, which cannot be forced deterministically from outside, so the
// transient failure is injected at the verifiedPackageData seam instead.
func TestCachePackage_RetriesVanishedEntry(t *testing.T) {
	repo := Repository{URI: fmt.Sprintf("%s/%s", testAlpineRepos, testArch)}
	repoWithIndex := repo.WithIndex(&APKIndex{Packages: []*Package{&testPkg}})
	pkg := NewRepositoryPackage(&testPkg, repoWithIndex)
	ctx := context.Background()

	vanishedENOENT := &os.PathError{Op: "open", Path: "whatever.dat.tar.gz", Err: syscall.ENOENT}
	vanishedEINVAL := &os.PathError{Op: "open", Path: "whatever.dat.tar.gz", Err: syscall.EINVAL}
	permanent := fmt.Errorf("data hash mismatch: expected aa, got bb")

	for _, tc := range []struct {
		name      string
		failures  []error
		wantCalls int
		wantErr   string
	}{
		{
			name:      "no failure reads once",
			wantCalls: 1,
		},
		{
			name:      "one transient ENOENT is retried",
			failures:  []error{vanishedENOENT},
			wantCalls: 2,
		},
		{
			name:      "two transient ENOENTs are retried",
			failures:  []error{vanishedENOENT, vanishedENOENT},
			wantCalls: 3,
		},
		{
			name:      "one transient EINVAL is retried",
			failures:  []error{vanishedEINVAL},
			wantCalls: 2,
		},
		{
			// Bounded: a third consecutive vanish is a real failure, not a
			// retry loop that spins while two processes fight over the entry.
			name:      "a persistently vanishing entry still fails",
			failures:  []error{vanishedENOENT, vanishedENOENT, vanishedENOENT},
			wantCalls: 3,
			wantErr:   "no such file or directory",
		},
		{
			// Anything that is not the vanish signature must not be retried,
			// or a tampered entry gets measured three times for one rejection.
			name:      "a verification failure is not retried",
			failures:  []error{permanent},
			wantCalls: 1,
			wantErr:   "data hash mismatch",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			globalApkCache.Forget(pkg.URL())
			t.Cleanup(func() { globalApkCache.Forget(pkg.URL()) })

			calls := 0
			orig := verifiedPackageData
			verifiedPackageData = func(exp *expandapk.APKExpanded, want []byte) (*os.File, error) {
				calls++
				if calls <= len(tc.failures) {
					return nil, tc.failures[calls-1]
				}
				return orig(exp, want)
			}
			t.Cleanup(func() { verifiedPackageData = orig })

			a := newDefaultPackageGetter(
				&http.Client{Transport: &testLocalTransport{root: testPrimaryPkgDir, basenameOnly: true}},
				&cache{dir: t.TempDir(), offline: false, shared: NewCache(false)},
				auth.DefaultAuthenticators)

			exp, err := a.GetPackage(ctx, pkg)

			require.Equal(t, tc.wantCalls, calls, "wrong number of verification reads")
			if tc.wantErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.wantErr, "wrong failure reason")
				require.Contains(t, err.Error(), "caching", "failure did not come from cachePackage")
				return
			}
			require.NoError(t, err, "a transient vanish must not fail the build")
			require.NotEmpty(t, fsNames(t, exp.TarFS), "recovered entry serves no contents")
		})
	}
}
