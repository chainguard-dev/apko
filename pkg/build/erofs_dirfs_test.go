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

package build

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	erofs "github.com/erofs/go-erofs"
	"github.com/stretchr/testify/require"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
)

// TestWriteErofs_DirFS writes an image from a dirFS rather than the memFS the
// other tests use. Real builds run on a dirFS, whose xattr lookups resolve
// against in-memory overrides seeded by walking the backing tree — so this is
// the path that would break if a walked entry were ever missing from those
// overrides (writeErofs treats a ListXattrs failure as fatal).
func TestWriteErofs_DirFS(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()

	require.NoError(t, os.MkdirAll(filepath.Join(base, "usr", "bin"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(base, "usr", "bin", "hello"), []byte("hi\n"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(base, "top"), []byte("top\n"), 0o644))
	require.NoError(t, os.Symlink("/usr/bin/hello", filepath.Join(base, "link")))

	fsys := apkfs.DirFS(ctx, base)
	require.NoError(t, fsys.SetXattr("usr/bin/hello", "user.marker", []byte("set")))

	out := filepath.Join(t.TempDir(), "image.erofs")
	f, err := os.Create(out)
	require.NoError(t, err)
	require.NoError(t, writeErofs(ctx, f, fsys, t.TempDir(), epoch))
	require.NoError(t, f.Close())

	rf, err := os.Open(out)
	require.NoError(t, err)
	defer rf.Close()
	img, err := erofs.Open(rf)
	require.NoError(t, err)

	for _, p := range []string{"usr/bin/hello", "top", "link"} {
		_, err := fs.Stat(img, p)
		require.NoError(t, err, "path %q missing from image", p)
	}

	data, err := fs.ReadFile(img, "top")
	require.NoError(t, err)
	require.Equal(t, "top\n", string(data))

	// The xattr set through the dirFS overrides must survive into the image.
	info, err := fs.Stat(img, "usr/bin/hello")
	require.NoError(t, err)
	st, ok := info.Sys().(*erofs.Stat)
	require.True(t, ok, "expected *erofs.Stat on Sys()")
	require.Equal(t, "set", st.Xattrs["user.marker"])
}
