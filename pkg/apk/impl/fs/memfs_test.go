package fs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMemFSMkdir(t *testing.T) {
	t.Run("parent non existent", func(t *testing.T) {
		var (
			m = NewMemFS()
		)
		err := m.Mkdir("/a/b", 0755)
		require.Error(t, err, os.ErrNotExist)
	})
	t.Run("parent file", func(t *testing.T) {
		var (
			m = NewMemFS()
		)
		err := m.Mkdir("/a", 0755)
		require.NoError(t, err)
		err = m.WriteFile("/a/b", []byte("hello"), 0644)
		require.NoError(t, err)
		err = m.Mkdir("/a/b/c", 0755)
		require.Error(t, err, os.ErrExist)
	})
	t.Run("already exists", func(t *testing.T) {
		var (
			m = NewMemFS()
		)
		err := m.Mkdir("/a", 0755)
		require.NoError(t, err)
		err = m.Mkdir("/a", 0755)
		require.Error(t, err, os.ErrExist)
	})
	t.Run("success", func(t *testing.T) {
		var (
			m = NewMemFS()
		)
		err := m.MkdirAll("/a/b", 0755)
		require.NoError(t, err)
		err = m.Mkdir("/a/b/c", 0755)
		require.NoError(t, err)
	})
}

func TestMemFSMkdirAll(t *testing.T) {
	t.Run("parent non existent", func(t *testing.T) {
		var (
			m = NewMemFS()
		)
		err := m.MkdirAll("/a/b", 0755)
		require.NoError(t, err)
	})
	t.Run("parent file", func(t *testing.T) {
		var (
			m = NewMemFS()
		)
		err := m.Mkdir("/a", 0755)
		require.NoError(t, err)
		err = m.WriteFile("/a/b", []byte("hello"), 0644)
		require.NoError(t, err)
		err = m.MkdirAll("/a/b/c", 0755)
		require.Error(t, err, os.ErrExist)
	})
	t.Run("already exists", func(t *testing.T) {
		var (
			m = NewMemFS()
		)
		err := m.Mkdir("/a", 0755)
		require.NoError(t, err)
		err = m.MkdirAll("/a", 0755)
		require.NoError(t, err)
	})
	t.Run("does not exist", func(t *testing.T) {
		var (
			m = NewMemFS()
		)
		err := m.MkdirAll("/a/b", 0755)
		require.NoError(t, err)
		err = m.Mkdir("/a/b/c", 0755)
		require.NoError(t, err)
	})
}

func TestMemFSCreateFile(t *testing.T) {
	t.Run("parent non existent", func(t *testing.T) {
		var (
			m = NewMemFS()
		)
		_, err := m.Create("/a/b")
		require.Error(t, err, os.ErrNotExist)
	})
	t.Run("parent file", func(t *testing.T) {
		var (
			m = NewMemFS()
		)
		err := m.Mkdir("/a", 0755)
		require.NoError(t, err)
		err = m.WriteFile("/a/b", []byte("hello"), 0644)
		require.NoError(t, err)
		_, err = m.Create("/a/b/c")
		require.Error(t, err, os.ErrExist)
	})
	t.Run("already exists dir", func(t *testing.T) {
		var (
			m = NewMemFS()
		)
		err := m.Mkdir("/a", 0755)
		require.NoError(t, err)
		_, err = m.Create("/a")
		require.Error(t, err, os.ErrExist)
	})
	t.Run("does not exist", func(t *testing.T) {
		var (
			m = NewMemFS()
		)
		err := m.MkdirAll("/a/b", 0755)
		require.NoError(t, err)
		_, err = m.Create("/a/b/c")
		require.NoError(t, err)
		dir, err := m.ReadDir("/a/b")
		require.NoError(t, err)
		require.Len(t, dir, 1)
	})
}

func TestMemFSWriteFile(t *testing.T) {
	t.Run("parent non existent", func(t *testing.T) {
		var (
			m = NewMemFS()
		)
		err := m.WriteFile("/a/b", []byte("hello"), 0644)
		require.Error(t, err, os.ErrNotExist)
	})
	t.Run("parent file", func(t *testing.T) {
		var (
			m = NewMemFS()
		)
		err := m.Mkdir("/a", 0755)
		require.NoError(t, err)
		err = m.WriteFile("/a/b", []byte("hello"), 0644)
		require.NoError(t, err)
		err = m.WriteFile("/a/b/c", []byte("hello"), 0644)
		require.Error(t, err, os.ErrExist)
	})
	t.Run("already exists dir", func(t *testing.T) {
		var (
			m = NewMemFS()
		)
		err := m.Mkdir("/a", 0755)
		require.NoError(t, err)
		err = m.WriteFile("/a/b/c", []byte("hello"), 0644)
		require.Error(t, err, os.ErrExist)
	})
	t.Run("does not exist", func(t *testing.T) {
		var (
			m       = NewMemFS()
			content = []byte("hello")
		)
		err := m.MkdirAll("/a/b", 0755)
		require.NoError(t, err)
		err = m.WriteFile("/a/b/c", content, 0644)
		require.NoError(t, err)
		dir, err := m.ReadDir("/a/b")
		require.NoError(t, err)
		require.Len(t, dir, 1)
		require.Equal(t, dir[0].Name(), "c")
		data, err := m.ReadFile("/a/b/c")
		require.NoError(t, err)
		require.Equal(t, data, content)
	})
}
func TestMemFSSymlink(t *testing.T) {
	var (
		m       = NewMemFS()
		base    = "/a/b/c"
		target  = filepath.Join(base, "d")
		link    = filepath.Join(base, "e")
		content = []byte("hello")
	)
	err := m.MkdirAll(base, 0755)
	require.NoError(t, err, "error creating dir %s", base)
	err = m.WriteFile(target, content, 0644)
	require.NoError(t, err, "error creating file %s", target)
	err = m.Symlink(target, link)
	require.NoError(t, err, "error creating symlink %s", link)
	// read the original file, then read the symlink, should get same content
	originalContent, err := m.ReadFile(target)
	require.NoError(t, err, "error reading target file content %s", target)
	linkContent, err := m.ReadFile(link)
	require.NoError(t, err, "error reading link file content %s", link)
	require.Equal(t, originalContent, linkContent, "content of %s should be %s", link, originalContent)
	// check if the link is an actual symlink, and the target of the link
	actualTarget, err := m.Readlink(link)
	require.NoError(t, err, "error reading target of link file %s", link)
	require.Equal(t, target, actualTarget, "target of %s should be %s", link, target)
}
func TestMemFSHardlink(t *testing.T) {
	var (
		m           = NewMemFS()
		base        = "/a/b/c"
		target      = filepath.Join(base, "d")
		linkSlash   = filepath.Join(base, "e")
		linkNoSlash = filepath.Join(base, "f")
		content     = []byte("hello")
	)
	err := m.MkdirAll(base, 0755)
	require.NoError(t, err, "error creating dir %s", base)
	err = m.WriteFile(target, content, 0644)
	require.NoError(t, err, "error creating file %s", target)
	// read the original file, then read the link, should get same content
	originalContent, err := m.ReadFile(target)
	require.NoError(t, err, "error reading target file content %s", target)

	t.Run("link with slash", func(t *testing.T) {
		linkName := linkSlash
		err = m.Link(target, linkName)
		require.NoError(t, err, "error creating hardlink %s", linkName)
		linkContent, err := m.ReadFile(linkName)
		require.NoError(t, err, "error reading link file content %s", linkName)
		require.Equal(t, originalContent, linkContent, "content of %s should be %s", linkName, originalContent)
	})
	t.Run("link with no slash", func(t *testing.T) {
		// linkNoSlash - remove the leading slash
		linkName := linkNoSlash
		target = target[1:]
		err = m.Link(target, linkName)
		require.NoError(t, err, "error creating hardlink %s", linkName)
		linkContent, err := m.ReadFile(linkName)
		require.NoError(t, err, "error reading link file content %s", linkName)
		require.Equal(t, originalContent, linkContent, "content of %s should be %s", linkName, originalContent)
	})
}

func TestMemFSMidLevelSymlink(t *testing.T) {
	var (
		basedir        = "/usr"
		truedir        = "lib"
		linkdir        = "lib64"
		subdir         = "subdir"
		filename       = "target"
		fullTruedir    = filepath.Join(basedir, truedir)
		fullLinkdir    = filepath.Join(basedir, linkdir)
		fullTrueSubdir = filepath.Join(fullTruedir, subdir)
		fullLinksubdir = filepath.Join(fullLinkdir, subdir)
		truefile       = filepath.Join(fullTrueSubdir, filename)
		linkfile       = filepath.Join(fullLinksubdir, filename)
		content        = []byte("hello")
	)
	t.Run("target in true dir", func(t *testing.T) {
		var (
			m = NewMemFS()
		)
		err := m.MkdirAll(fullTruedir, 0755)
		require.NoError(t, err, "error creating dir %s", basedir)
		err = m.Symlink(truedir, fullLinkdir)
		require.NoError(t, err, "error creating directory symlink %s", fullLinkdir)
		err = m.Mkdir(fullTrueSubdir, 0755)
		require.NoError(t, err, "error creating dir %s", fullTrueSubdir)
		err = m.WriteFile(truefile, content, 0644)
		require.NoError(t, err, "error creating file %s", truefile)
		// read the original file, then read the symlink, should get same content
		originalContent, err := m.ReadFile(truefile)
		require.NoError(t, err, "error reading target file content %s", truefile)
		linkContent, err := m.ReadFile(linkfile)
		require.NoError(t, err, "error reading link file content %s", linkfile)
		require.Equal(t, originalContent, linkContent, "content of %s should be %s", linkfile, originalContent)
		// check if the link is an actual symlink, and the target of the link
		actualTarget, err := m.Readlink(fullLinkdir)
		require.NoError(t, err, "error reading target of link file %s", fullLinkdir)
		require.Equal(t, truedir, actualTarget, "target of %s should be %s", fullLinkdir, truedir)
	})
	t.Run("target in symlink dir", func(t *testing.T) {
		var (
			m = NewMemFS()
		)
		err := m.MkdirAll(fullTruedir, 0755)
		require.NoError(t, err, "error creating dir %s", basedir)
		err = m.Symlink(truedir, fullLinkdir)
		require.NoError(t, err, "error creating directory symlink %s", fullLinkdir)
		err = m.Mkdir(fullLinksubdir, 0755)
		require.NoError(t, err, "error creating dir %s", fullLinksubdir)
		err = m.WriteFile(linkfile, content, 0644)
		require.NoError(t, err, "error creating file %s", truefile)
		// read the original file, then read the symlink, should get same content
		originalContent, err := m.ReadFile(truefile)
		require.NoError(t, err, "error reading target file content %s", truefile)
		linkContent, err := m.ReadFile(linkfile)
		require.NoError(t, err, "error reading link file content %s", linkfile)
		require.Equal(t, originalContent, linkContent, "content of %s should be %s", linkfile, originalContent)
		// check if the link is an actual symlink, and the target of the link
		actualTarget, err := m.Readlink(fullLinkdir)
		require.NoError(t, err, "error reading target of link file %s", fullLinkdir)
		require.Equal(t, truedir, actualTarget, "target of %s should be %s", fullLinkdir, truedir)
	})
}
