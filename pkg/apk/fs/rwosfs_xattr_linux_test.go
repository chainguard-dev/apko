// Copyright 2026 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux

package fs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

const testXattr = "user.apko-test"

// skipWithoutUserXattrs skips if xattrs cannot be written to disk here: no
// procfs, or the filesystem holding dir does not support user.* (e.g. an
// older tmpfs).
func skipWithoutUserXattrs(t *testing.T, dir string) {
	t.Helper()
	if err := checkXattrsOnDisk(); err != nil {
		t.Skip(err)
	}
	probe := filepath.Join(dir, ".xattr-probe")
	require.NoError(t, os.WriteFile(probe, nil, 0o600))
	defer os.Remove(probe)
	if err := unix.Setxattr(probe, testXattr, []byte("x"), 0); err != nil {
		if errors.Is(err, unix.ENOTSUP) {
			t.Skipf("user xattrs unsupported in %s", dir)
		}
		require.NoError(t, err)
	}
}

// diskXattr returns the value of testXattr on p, or nil if it is not set.
func diskXattr(t *testing.T, p string) []byte {
	t.Helper()
	buf := make([]byte, 256)
	n, err := unix.Lgetxattr(p, testXattr, buf)
	if errors.Is(err, unix.ENODATA) {
		return nil
	}
	require.NoError(t, err)
	return buf[:n]
}

func TestDirFSXattrsOnDisk(t *testing.T) {
	dir := t.TempDir()
	skipWithoutUserXattrs(t, dir)
	fsys := DirFS(t.Context(), dir, DirFSWithXattrsOnDisk())
	require.NotNil(t, fsys)
	require.NoError(t, fsys.MkdirAll("etc", 0o755))
	require.NoError(t, fsys.WriteFile("etc/file", []byte("x"), 0o644))

	for _, name := range []string{"etc/file", "etc", "/"} {
		real := filepath.Join(dir, name)
		require.NoError(t, fsys.SetXattr(name, testXattr, []byte("v1")))
		assert.Equal(t, []byte("v1"), diskXattr(t, real), name)
		got, err := fsys.GetXattr(name, testXattr)
		require.NoError(t, err)
		assert.Equal(t, []byte("v1"), got, name)

		require.NoError(t, fsys.RemoveXattr(name, testXattr))
		assert.Nil(t, diskXattr(t, real), name)
	}
}

func TestDirFSXattrsMemoryOnlyByDefault(t *testing.T) {
	dir := t.TempDir()
	skipWithoutUserXattrs(t, dir)
	fsys := DirFS(t.Context(), dir)
	require.NotNil(t, fsys)
	require.NoError(t, fsys.WriteFile("file", []byte("x"), 0o644))
	require.NoError(t, fsys.SetXattr("file", testXattr, []byte("v")))
	got, err := fsys.GetXattr("file", testXattr)
	require.NoError(t, err)
	assert.Equal(t, []byte("v"), got)
	assert.Nil(t, diskXattr(t, filepath.Join(dir, "file")))
}

// TestDirFSXattrsStayInRoot checks that neither a symlink pointing out of the
// root nor a ".." path can direct an xattr write at something outside it.
func TestDirFSXattrsStayInRoot(t *testing.T) {
	outer := t.TempDir()
	skipWithoutUserXattrs(t, outer)
	dir := filepath.Join(outer, "root")
	require.NoError(t, os.Mkdir(dir, 0o755))
	outside := filepath.Join(outer, "outside")
	require.NoError(t, os.WriteFile(outside, nil, 0o644))

	fsys := DirFS(t.Context(), dir, DirFSWithXattrsOnDisk())
	require.NotNil(t, fsys)
	require.NoError(t, fsys.MkdirAll("sub", 0o755))
	require.NoError(t, os.Symlink(outside, filepath.Join(dir, "abs-link")))
	require.NoError(t, os.Symlink("../outside", filepath.Join(dir, "rel-link")))
	require.NoError(t, os.Symlink(outer, filepath.Join(dir, "dir-link")))

	// The kernel refuses user.* on a symlink itself; that EPERM is
	// tolerated, so these may succeed, but must not touch the target.
	for _, name := range []string{"abs-link", "rel-link"} {
		_ = fsys.SetXattr(name, testXattr, []byte("escaped"))
		assert.Nil(t, diskXattr(t, outside), name)
	}
	for _, name := range []string{"..", "../", "sub/../..", "/../outside", "dir-link/outside"} {
		assert.Error(t, fsys.SetXattr(name, testXattr, []byte("escaped")), name)
		assert.Nil(t, diskXattr(t, outer), name)
		assert.Nil(t, diskXattr(t, outside), name)
	}
}

// TestDirFSXattrsUnwritable checks that, unprivileged, a file or parent
// directory the process cannot write or read is tolerated like EPERM, as for
// Chown, rather than failing the install.
func TestDirFSXattrsUnwritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses permission checks")
	}
	dir := t.TempDir()
	skipWithoutUserXattrs(t, dir)
	fsys := DirFS(t.Context(), dir, DirFSWithXattrsOnDisk())
	require.NotNil(t, fsys)
	require.NoError(t, fsys.MkdirAll("noread", 0o755))
	require.NoError(t, fsys.WriteFile("noread/file", []byte("x"), 0o644))
	require.NoError(t, fsys.WriteFile("readonly", []byte("x"), 0o644))
	require.NoError(t, os.Chmod(filepath.Join(dir, "readonly"), 0o444))
	require.NoError(t, os.Chmod(filepath.Join(dir, "noread"), 0o311))
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(dir, "noread"), 0o755) })

	require.NoError(t, fsys.SetXattr("readonly", testXattr, []byte("v")))
	require.NoError(t, fsys.RemoveXattr("readonly", testXattr))
	// The parent is opened O_PATH, so this one does reach the disk.
	require.NoError(t, fsys.SetXattr("noread/file", testXattr, []byte("v")))
	assert.Equal(t, []byte("v"), diskXattr(t, filepath.Join(dir, "noread", "file")))
}
