package apk

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/klauspost/compress/gzip"
	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/apk/auth"
)

// TestCachePackage_SurvivesDataEntryDisturbedAfterPublish covers parallel
// builds sharing a cache directory. Once cachePackage has published the data
// entry, another process may republish it at any moment, and what this one
// then finds at the published name is not something it controls. Each row
// disturbs the entry the instant after cachePackage publishes it, in one of the
// ways a concurrent publisher really does, and requires that the build still
// succeeds and serves exactly the bytes that verified.
//
// The disturbances:
//
//   - vanished: the entry's target is unlinked, which is what a concurrent
//     ReplaceCachedFile's orphan cleanup does to the copy it displaced. A reader
//     that resolved the link just before that sees ENOENT.
//   - a directory: on ext4 and btrfs, open() through a symlink that is being
//     renamed over can return the link's parent directory, which reads as
//     "not a regular file".
//   - other content: another writer's bytes, valid gzip but not this package.
//     Nothing at the published name may be served, nor fail a download that
//     already verified.
func TestCachePackage_SurvivesDataEntryDisturbedAfterPublish(t *testing.T) {
	repo := Repository{URI: fmt.Sprintf("%s/%s", testAlpineRepos, testArch)}
	pkg := NewRepositoryPackage(&testPkg, repo.WithIndex(&APKIndex{Packages: []*Package{&testPkg}}))
	ctx := context.Background()

	vanish := func(t *testing.T, dst string) {
		target, err := os.Readlink(dst)
		require.NoError(t, err, "published entry %q is not a symlink", dst)
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(dst), target)
		}
		require.NoError(t, os.Remove(target))
	}
	repoint := func(t *testing.T, dst, target string) {
		tmp := dst + ".disturb"
		require.NoError(t, os.Symlink(target, tmp))
		require.NoError(t, os.Rename(tmp, dst))
	}
	becomeDirectory := func(t *testing.T, dst string) { repoint(t, dst, ".") }
	becomeOtherContent := func(t *testing.T, dst string) {
		var tb bytes.Buffer
		tw := tar.NewWriter(&tb)
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: "planted", Mode: 0o644, Size: 7}))
		_, err := tw.Write([]byte("planted"))
		require.NoError(t, err)
		require.NoError(t, tw.Close())
		var gb bytes.Buffer
		zw := gzip.NewWriter(&gb)
		_, err = zw.Write(tb.Bytes())
		require.NoError(t, err)
		require.NoError(t, zw.Close())
		other := filepath.Join(filepath.Dir(dst), "other-writer.tar.gz")
		require.NoError(t, os.WriteFile(other, gb.Bytes(), 0o644))
		repoint(t, dst, filepath.Base(other))
	}

	get := func(t *testing.T, disturb func(*testing.T, string)) ([]string, error) {
		globalApkCache.Forget(pkg.URL())
		t.Cleanup(func() { globalApkCache.Forget(pkg.URL()) })

		orig := replaceCachedFile
		replaceCachedFile = func(src, dst string) error {
			if err := orig(src, dst); err != nil {
				return err
			}
			if disturb != nil && strings.HasSuffix(dst, ".dat.tar.gz") {
				disturb(t, dst)
			}
			return nil
		}
		t.Cleanup(func() { replaceCachedFile = orig })

		a := newDefaultPackageGetter(
			&http.Client{Transport: &testLocalTransport{root: testPrimaryPkgDir, basenameOnly: true}},
			&cache{dir: t.TempDir(), offline: false, shared: NewCache(false)},
			auth.DefaultAuthenticators)
		exp, err := a.GetPackage(ctx, pkg)
		if err != nil {
			return nil, err
		}
		return fsNames(t, exp.TarFS), nil
	}

	want, err := get(t, nil)
	require.NoError(t, err, "undisturbed baseline")
	require.NotEmpty(t, want, "undisturbed baseline serves no contents")

	for _, tc := range []struct {
		name    string
		disturb func(*testing.T, string)
	}{
		{"entry vanished after publish", vanish},
		{"entry became a directory after publish", becomeDirectory},
		{"entry became other content after publish", becomeOtherContent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := get(t, tc.disturb)
			require.NoError(t, err, "a disturbed data entry failed a download that had already verified")
			require.True(t, slices.Equal(want, got),
				"served data differs from what verified:\nwant %v\ngot  %v", want, got)
		})
	}
}
