package fs

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestMemFSLstatReportsSymlinkMode covers the bug described in
// chainguard-dev/apko#1543 ("Replaces of symlinks does not appear to work"):
// Lstat must report the ModeSymlink bit for a path that is itself a symlink
// (POSIX lstat semantics - it must NOT follow the final path component). The
// previous implementation delegated straight to getNode(), which always
// resolves symlinks including the final component, so the returned
// fs.FileInfo looked like a regular file instead of a symlink.
func TestMemFSLstatReportsSymlinkMode(t *testing.T) {
	var (
		m      = NewMemFS()
		base   = "/a/b/c"
		target = filepath.Join(base, "d")
		link   = filepath.Join(base, "e")
	)
	require.NoError(t, m.MkdirAll(base, 0o755))
	require.NoError(t, m.WriteFile(target, []byte("hello"), 0o644))
	require.NoError(t, m.Symlink(target, link))

	fi, err := m.Lstat(link)
	require.NoError(t, err, "Lstat on a symlink path must succeed")

	require.NotZero(t, fi.Mode()&fs.ModeSymlink,
		"Lstat(%q) must report the ModeSymlink bit for a symlink; got mode %v (bug: apko#1543 / memfs.go Lstat)",
		link, fi.Mode())
}

// TestMemFSStatStillResolvesSymlink is a regression guard: Stat (unlike Lstat)
// must keep following the final path component through a symlink to the
// target's own info, exactly as before this change.
func TestMemFSStatStillResolvesSymlink(t *testing.T) {
	var (
		m      = NewMemFS()
		base   = "/a/b/c"
		target = filepath.Join(base, "d")
		link   = filepath.Join(base, "e")
	)
	require.NoError(t, m.MkdirAll(base, 0o755))
	require.NoError(t, m.WriteFile(target, []byte("hello"), 0o644))
	require.NoError(t, m.Symlink(target, link))

	fi, err := m.Stat(link)
	require.NoError(t, err, "Stat on a symlink path must succeed")
	require.Zero(t, fi.Mode()&fs.ModeSymlink,
		"Stat(%q) must resolve the symlink and report the target's mode, not ModeSymlink; got %v",
		link, fi.Mode())
	require.Equal(t, int64(len("hello")), fi.Size(), "Stat must report the target file's size")
}

// TestMemFSLstatFollowsIntermediateSymlinks is a regression guard for the fix:
// Lstat must still resolve symlinks that appear in INTERMEDIATE path
// components (only the final component is exempt from resolution).
func TestMemFSLstatFollowsIntermediateSymlinks(t *testing.T) {
	var (
		m           = NewMemFS()
		basedir     = "/usr"
		truedir     = "lib"
		linkdir     = "lib64"
		fullTruedir = filepath.Join(basedir, truedir)
		fullLinkdir = filepath.Join(basedir, linkdir)
		filename    = "target"
		truefile    = filepath.Join(fullTruedir, filename)
		linkedPath  = filepath.Join(fullLinkdir, filename)
		content     = []byte("hello")
	)
	require.NoError(t, m.MkdirAll(fullTruedir, 0o755))
	require.NoError(t, m.Symlink(truedir, fullLinkdir))
	require.NoError(t, m.WriteFile(truefile, content, 0o644))

	fi, err := m.Lstat(linkedPath)
	require.NoError(t, err, "Lstat through an intermediate directory symlink must still resolve the intermediate component")
	require.Zero(t, fi.Mode()&fs.ModeSymlink,
		"Lstat(%q) names a regular file reached via an intermediate symlink; it must NOT itself be reported as a symlink, got %v",
		linkedPath, fi.Mode())
	require.Equal(t, int64(len(content)), fi.Size())
}
