package apk

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/apk/auth"
	"chainguard.dev/apko/pkg/apk/expandapk"
)

// TestCachePackage_FailureReleasesEverything pins what cachePackage must let go
// of when publishing fails part way. By then exp's TarFS is the verified
// private copy ExpandApk inflated, its only data, and its temp directory sits
// in the shared cache directory where nothing will ever reference or remove
// it, so a failed publish has to close the one and remove the other.
func TestCachePackage_FailureReleasesEverything(t *testing.T) {
	repo := Repository{URI: fmt.Sprintf("%s/%s", testAlpineRepos, testArch)}
	pkg := NewRepositoryPackage(&testPkg, repo.WithIndex(&APKIndex{Packages: []*Package{&testPkg}}))
	injected := errors.New("injected publish failure")

	// openFDs counts this process's descriptors where the platform exposes
	// them, so a leak shows up as a difference rather than needing a handle on
	// the descriptor itself.
	openFDs := func() (int, bool) {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			return 0, false
		}
		return len(entries), true
	}

	for _, tc := range []struct {
		name string
		// setup runs on the freshly fetched exp before cachePackage.
		setup func(t *testing.T, exp *expandapk.APKExpanded)
		// failPublish, if non-zero, makes that publish call (1-based) fail.
		failPublish     int
		wantErr         string
		wantErrIs       error
		wantPublishes   int
		wantTempDirGone bool
		// checkFDs compares descriptor counts before and after, for failures
		// where there is no handle left to inspect.
		checkFDs bool
	}{
		{name: "control publish failure releases the private copy", failPublish: 1, wantErrIs: injected, wantPublishes: 1, wantTempDirGone: true},
		{name: "signature publish failure releases the private copy", failPublish: 2, wantErrIs: injected, wantPublishes: 2, wantTempDirGone: true},
		{name: "data publish failure releases the private copy", failPublish: 3, wantErrIs: injected, wantPublishes: 3, wantTempDirGone: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newDefaultPackageGetter(
				&http.Client{Transport: &testLocalTransport{root: testPrimaryPkgDir, basenameOnly: true}},
				nil, auth.DefaultAuthenticators)
			cacheDir := t.TempDir()
			exp, err := d.doFetchExpandAndVerify(context.Background(), pkg, cacheDir, nil)
			require.NoError(t, err)
			require.NotEmpty(t, exp.SignatureFile, "fixture must be signed for the three-publish rows to mean what they say")
			tempDir := filepath.Dir(exp.PackageFile)
			original, _ := exp.TarFS.UnderlyingReader().(*os.File)

			if tc.setup != nil {
				tc.setup(t, exp)
			}

			var private *os.File
			publishes := 0
			orig := replaceCachedFile
			replaceCachedFile = func(src, dst string) error {
				publishes++
				private, _ = exp.TarFS.UnderlyingReader().(*os.File)
				if publishes == tc.failPublish {
					return injected
				}
				return orig(src, dst)
			}
			t.Cleanup(func() { replaceCachedFile = orig })

			before, haveFDs := openFDs()
			got, err := d.cachePackage(context.Background(), pkg, exp, cacheDir)
			after, _ := openFDs()

			require.Nil(t, got, "a failed cachePackage returned a package")
			require.Error(t, err)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
			}
			if tc.wantErrIs != nil {
				require.ErrorIs(t, err, tc.wantErrIs)
			}
			require.Equal(t, tc.wantPublishes, publishes, "publish calls (err=%v)", err)

			if original != nil {
				_, statErr := original.Stat()
				require.ErrorIs(t, statErr, os.ErrClosed, "original TarFS descriptor left open (err=%v)", err)
			}
			if private != nil && private != original {
				_, statErr := private.Stat()
				require.ErrorIs(t, statErr, os.ErrClosed, "verified private copy left open (err=%v)", err)
			}
			if tc.wantTempDirGone {
				_, statErr := os.Stat(tempDir)
				require.ErrorIs(t, statErr, os.ErrNotExist, "temp dir %q left in the cache dir (err=%v)", tempDir, err)
			}
			if tc.checkFDs && haveFDs {
				require.Equal(t, before, after, "descriptor count changed across a failed cachePackage (err=%v)", err)
			}
		})
	}
}
