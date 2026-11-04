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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/apk/expandapk"
	apkfs "chainguard.dev/apko/pkg/apk/fs"
)

// TestGetPackage_OfflineReadOnlyCache builds offline over a cache nobody can
// write to, the shape rules_apko hands apko under Bazel remote execution, and
// requires that it succeeds and leaves every byte of the cache as it was.
func TestGetPackage_OfflineReadOnlyCache(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory modes do not restrict writes on windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root; directory modes do not restrict us")
	}

	repo := Repository{URI: fmt.Sprintf("%s/%s", testAlpineRepos, testArch)}
	repoWithIndex := repo.WithIndex(&APKIndex{Packages: []*Package{&testPkg}})
	pkg := NewRepositoryPackage(&testPkg, repoWithIndex)

	apkPath := filepath.Join(testPrimaryPkgDir, testPkgFilename)
	want := expandTestPackage(t, apkPath)

	for _, tc := range []struct {
		name string
		// sections lays out the apk's gzip sections beside the .apk as
		// rules_apko's apk_import does: control, signature and compressed
		// data, without the uncompressed tar apko itself would add.
		sections bool
	}{
		{name: "rules_apko layout", sections: true},
		{name: "apk files only", sections: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			repoDir := filepath.Join(root, url.QueryEscape(testAlpineRepos), testArch)
			require.NoError(t, os.MkdirAll(repoDir, 0o755))

			apkBytes, err := os.ReadFile(apkPath)
			require.NoError(t, err)
			cachedAPK := filepath.Join(repoDir, testPkgFilename)
			require.NoError(t, os.WriteFile(cachedAPK, apkBytes, 0o644)) //nolint:gosec // test fixture

			if tc.sections {
				pkgDir := strings.TrimSuffix(cachedAPK, ".apk")
				require.NoError(t, os.MkdirAll(pkgDir, 0o755))
				ctlHex := hex.EncodeToString(want.ControlHash)
				copyFile(t, want.ControlFile, filepath.Join(pkgDir, ctlHex+".ctl.tar.gz"))
				if want.SignatureFile != "" {
					copyFile(t, want.SignatureFile, filepath.Join(pkgDir, ctlHex+".sig.tar.gz"))
				}
				copyFile(t, want.PackageFile, filepath.Join(pkgDir, hex.EncodeToString(want.PackageHash)+".dat.tar.gz"))
			}

			makeReadOnly(t, root)
			before := snapshotTree(t, root)

			globalApkCache.Forget(pkg.URL())
			t.Cleanup(func() { globalApkCache.Forget(pkg.URL()) })

			a, err := New(t.Context(),
				WithFS(apkfs.NewMemFS()),
				WithIgnoreMknodErrors(ignoreMknodErrors),
				WithOffline(true),
				WithCache(root, true, NewCache(false)),
			)
			require.NoError(t, err)

			exp, err := a.packageGetter.GetPackage(t.Context(), pkg)
			require.NoError(t, err, "offline build over a read-only cache")
			require.Equal(t, fsNames(t, want.TarFS), fsNames(t, exp.TarFS))

			require.Equal(t, before, snapshotTree(t, root), "offline build changed the read-only cache")
		})
	}
}

func expandTestPackage(t *testing.T, path string) *expandapk.APKExpanded {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	exp, err := expandapk.ExpandApk(t.Context(), f, t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { _ = exp.Close() })
	return exp
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(dst, b, 0o644)) //nolint:gosec // test fixture
}

// makeReadOnly strips write permission from everything under root, and
// restores it at cleanup so t.TempDir can remove the tree.
func makeReadOnly(t *testing.T, root string) {
	t.Helper()
	setModes := func(dirMode, fileMode fs.FileMode) error {
		return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return os.Chmod(path, dirMode)
			}
			return os.Chmod(path, fileMode)
		})
	}
	require.NoError(t, setModes(0o555, 0o444))
	t.Cleanup(func() { _ = setModes(0o755, 0o644) })
}

// snapshotTree records every entry under root with its mode, and the content
// digest of every regular file.
func snapshotTree(t *testing.T, root string) map[string]string {
	t.Helper()
	snap := map[string]string{}
	require.NoError(t, filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		entry := info.Mode().String()
		if info.Mode().IsRegular() {
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(b)
			entry += " " + hex.EncodeToString(sum[:])
		}
		snap[rel] = entry
		return nil
	}))
	return snap
}
