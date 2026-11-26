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
	"chainguard.dev/apko/pkg/apk/expandapk/tarfs"
)

// openExpanded returns an APKExpanded whose TarFS is backed by an open file,
// which is what the cache has to close.
func openExpanded(t *testing.T) (*expandapk.APKExpanded, *os.File) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "data")
	require.NoError(t, err)
	t.Cleanup(func() { f.Close() })
	tfs, err := tarfs.New(f, 0)
	require.NoError(t, err)
	return &expandapk.APKExpanded{TarFS: tfs}, f
}

func isClosed(f *os.File) bool {
	_, err := f.Stat()
	return errors.Is(err, os.ErrClosed)
}

func TestPackageCache_LastReleaseCloses(t *testing.T) {
	c := newPackageCache(8)
	exp, f := openExpanded(t)
	calls := 0
	load := func() (*expandapk.APKExpanded, error) { calls++; return exp, nil }

	got1, hit, r1, err := c.acquire("k", load)
	require.NoError(t, err)
	require.False(t, hit)
	got2, hit, r2, err := c.acquire("k", load)
	require.NoError(t, err)
	require.True(t, hit)
	require.Same(t, got1, got2)
	require.Equal(t, 1, calls)

	r1.Release()
	r1.Release() // idempotent; must not drop r2's reference
	require.False(t, isClosed(f), "closed while still held")

	r2.Release()
	require.True(t, isClosed(f), "not closed after last release")
	require.Equal(t, 0, c.lru.Len(), "released entry still cached")
}

func TestPackageCache_ForgottenEntryClosesOnRelease(t *testing.T) {
	c := newPackageCache(8)
	exp, f := openExpanded(t)
	_, _, r, err := c.acquire("k", func() (*expandapk.APKExpanded, error) { return exp, nil })
	require.NoError(t, err)

	c.Forget("k")
	require.False(t, isClosed(f), "forget closed a held entry")

	// A new acquire must not find the forgotten entry.
	exp2, _ := openExpanded(t)
	got, hit, r2, err := c.acquire("k", func() (*expandapk.APKExpanded, error) { return exp2, nil })
	require.NoError(t, err)
	require.False(t, hit)
	require.Same(t, exp2, got)

	r.Release()
	require.True(t, isClosed(f))

	// Releasing the stale reference must not remove the new entry.
	require.Equal(t, 1, c.lru.Len())
	r2.Release()
}

func TestPackageCache_EvictionClosesOnlyUnheld(t *testing.T) {
	c := newPackageCache(1)
	exp1, f1 := openExpanded(t)
	exp2, f2 := openExpanded(t)

	_, _, r1, err := c.acquire("a", func() (*expandapk.APKExpanded, error) { return exp1, nil })
	require.NoError(t, err)
	_, _, r2, err := c.acquire("b", func() (*expandapk.APKExpanded, error) { return exp2, nil })
	require.NoError(t, err)

	require.False(t, isClosed(f1), "evicted entry closed while held")
	r1.Release()
	require.True(t, isClosed(f1))
	require.False(t, isClosed(f2))
	r2.Release()
	require.True(t, isClosed(f2))
}

func TestPackageCache_ErrorsAreNotCached(t *testing.T) {
	c := newPackageCache(8)
	_, _, r, err := c.acquire("k", func() (*expandapk.APKExpanded, error) { return nil, fmt.Errorf("boom") })
	require.Error(t, err)
	require.Nil(t, r)
	require.Equal(t, 0, c.lru.Len())
}

// TestGetPackage_CloseReleasesCachedDescriptors is the regression test for
// chainguard-dev/apko#2651: with a disk cache, every package's private data
// copy stayed open for the life of the process.
func TestGetPackage_CloseReleasesCachedDescriptors(t *testing.T) {
	repo := Repository{URI: fmt.Sprintf("%s/%s", testAlpineRepos, testArch)}
	repoWithIndex := repo.WithIndex(&APKIndex{Packages: []*Package{&testPkg}})
	pkg := NewRepositoryPackage(&testPkg, repoWithIndex)
	ctx := context.Background()

	globalApkCache.Forget(pkg.URL())
	t.Cleanup(func() { globalApkCache.Forget(pkg.URL()) })

	tmpDir := t.TempDir()
	newGetter := func() *defaultPackageGetter {
		return newDefaultPackageGetter(
			&http.Client{Transport: &testLocalTransport{root: testPrimaryPkgDir, basenameOnly: true}},
			&cache{dir: tmpDir, shared: NewCache(false)},
			auth.DefaultAuthenticators)
	}
	g1, g2 := newGetter(), newGetter()

	exp1, err := g1.GetPackage(ctx, pkg)
	require.NoError(t, err)
	exp2, err := g2.GetPackage(ctx, pkg)
	require.NoError(t, err)
	require.Same(t, exp1, exp2, "second getter should share the cached entry")

	f, ok := exp1.TarFS.UnderlyingReader().(*os.File)
	require.True(t, ok)

	require.NoError(t, g1.Close())
	require.False(t, isClosed(f), "closed while another getter still holds it")

	require.NoError(t, g2.Close())
	require.True(t, isClosed(f), "descriptor still open after every getter closed")

	// The expansion temp dirs under the cache dir are gone too.
	leftovers, err := filepath.Glob(filepath.Join(tmpDir, "*", "*", "*", "expand-apk*"))
	require.NoError(t, err)
	require.Empty(t, leftovers)

	// The package is still served from the disk cache afterwards.
	g3 := newGetter()
	exp3, err := g3.GetPackage(ctx, pkg)
	require.NoError(t, err)
	require.NotSame(t, exp1, exp3)
	require.NoError(t, g3.Close())
}
