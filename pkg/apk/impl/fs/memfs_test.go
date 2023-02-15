package fs

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

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
	actualTarget, isLink, err := m.Readlink(link)
	require.NoError(t, err, "error reading target of link file %s", link)
	require.True(t, isLink, "file %s should be a symlink", link)
	require.Equal(t, target, actualTarget, "target of %s should be %s", link, target)
}
func TestMemFSHardlink(t *testing.T) {
	var (
		m           = NewMemFS().(*memFS)
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
		// check if the link is an actual hardlink, and the target of the link
		actualTarget, isLink, err := m.readHardlink(linkName)
		require.NoError(t, err, "error reading target of link file %s", linkName)
		require.True(t, isLink, "file %s should be a hardlink", linkName)
		target = filepath.Clean(fmt.Sprintf("%c%s", filepath.Separator, target))
		require.Equal(t, target, actualTarget, "target of %s should be %s", linkName, target)
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
		// check if the link is an actual hardlink, and the target of the link
		actualTarget, isLink, err := m.readHardlink(linkName)
		require.NoError(t, err, "error reading target of link file %s", linkName)
		require.True(t, isLink, "file %s should be a hardlink", linkName)
		target = filepath.Clean(fmt.Sprintf("%c%s", filepath.Separator, target))
		require.Equal(t, target, actualTarget, "target of %s should be %s", linkName, target)
	})
}
