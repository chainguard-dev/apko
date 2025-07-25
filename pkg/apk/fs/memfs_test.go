package fs

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

type testDirEntry struct {
	path    string
	perms   os.FileMode
	dir     bool
	content []byte
}

func TestMemFSMkdir(t *testing.T) {
	t.Run("parent non existent", func(t *testing.T) {
		var (
			m = NewMemFS()
		)
		err := m.Mkdir("/a/b", 0o755)
		require.Error(t, err, os.ErrNotExist)
	})
	t.Run("parent file", func(t *testing.T) {
		var (
			m = NewMemFS()
		)
		err := m.Mkdir("/a", 0o755)
		require.NoError(t, err)
		err = m.WriteFile("/a/b", []byte("hello"), 0o644)
		require.NoError(t, err)
		err = m.Mkdir("/a/b/c", 0o755)
		require.Error(t, err, os.ErrExist)
	})
	t.Run("already exists", func(t *testing.T) {
		var (
			m = NewMemFS()
		)
		err := m.Mkdir("/a", 0o755)
		require.NoError(t, err)
		err = m.Mkdir("/a", 0o755)
		require.Error(t, err, os.ErrExist)
	})
	t.Run("success", func(t *testing.T) {
		var (
			m = NewMemFS()
		)
		err := m.MkdirAll("/a/b", 0o755)
		require.NoError(t, err)
		err = m.Mkdir("/a/b/c", 0o755)
		require.NoError(t, err)
	})
}

func TestMemFSMkdirAll(t *testing.T) {
	t.Run("parent non existent", func(t *testing.T) {
		var (
			m = NewMemFS()
		)
		err := m.MkdirAll("/a/b", 0o755)
		require.NoError(t, err)
	})
	t.Run("parent file", func(t *testing.T) {
		var (
			m = NewMemFS()
		)
		err := m.Mkdir("/a", 0o755)
		require.NoError(t, err)
		err = m.WriteFile("/a/b", []byte("hello"), 0o644)
		require.NoError(t, err)
		err = m.MkdirAll("/a/b/c", 0o755)
		require.Error(t, err, os.ErrExist)
	})
	t.Run("already exists", func(t *testing.T) {
		var (
			m = NewMemFS()
		)
		err := m.Mkdir("/a", 0o755)
		require.NoError(t, err)
		err = m.MkdirAll("/a", 0o755)
		require.NoError(t, err)
	})
	t.Run("does not exist", func(t *testing.T) {
		var (
			m = NewMemFS()
		)
		err := m.MkdirAll("/a/b", 0o755)
		require.NoError(t, err)
		err = m.Mkdir("/a/b/c", 0o755)
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
		err := m.Mkdir("/a", 0o755)
		require.NoError(t, err)
		err = m.WriteFile("/a/b", []byte("hello"), 0o644)
		require.NoError(t, err)
		_, err = m.Create("/a/b/c")
		require.Error(t, err, os.ErrExist)
	})
	t.Run("already exists dir", func(t *testing.T) {
		var (
			m = NewMemFS()
		)
		err := m.Mkdir("/a", 0o755)
		require.NoError(t, err)
		_, err = m.Create("/a")
		require.Error(t, err, os.ErrExist)
	})
	t.Run("does not exist", func(t *testing.T) {
		var (
			m = NewMemFS()
		)
		err := m.MkdirAll("/a/b", 0o755)
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
		err := m.WriteFile("/a/b", []byte("hello"), 0o644)
		require.Error(t, err, os.ErrNotExist)
	})
	t.Run("parent file", func(t *testing.T) {
		var (
			m = NewMemFS()
		)
		err := m.Mkdir("/a", 0o755)
		require.NoError(t, err)
		err = m.WriteFile("/a/b", []byte("hello"), 0o644)
		require.NoError(t, err)
		err = m.WriteFile("/a/b/c", []byte("hello"), 0o644)
		require.Error(t, err, os.ErrExist)
	})
	t.Run("already exists dir", func(t *testing.T) {
		var (
			m = NewMemFS()
		)
		err := m.Mkdir("/a", 0o755)
		require.NoError(t, err)
		err = m.WriteFile("/a/b/c", []byte("hello"), 0o644)
		require.Error(t, err, os.ErrExist)
	})
	t.Run("does not exist", func(t *testing.T) {
		var (
			m       = NewMemFS()
			content = []byte("hello")
		)
		err := m.MkdirAll("/a/b", 0o755)
		require.NoError(t, err)
		err = m.WriteFile("/a/b/c", content, 0o644)
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
	err := m.MkdirAll(base, 0o755)
	require.NoError(t, err, "error creating dir %s", base)
	err = m.WriteFile(target, content, 0o644)
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
	err := m.MkdirAll(base, 0o755)
	require.NoError(t, err, "error creating dir %s", base)
	err = m.WriteFile(target, content, 0o644)
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
		err := m.MkdirAll(fullTruedir, 0o755)
		require.NoError(t, err, "error creating dir %s", basedir)
		err = m.Symlink(truedir, fullLinkdir)
		require.NoError(t, err, "error creating directory symlink %s", fullLinkdir)
		err = m.Mkdir(fullTrueSubdir, 0o755)
		require.NoError(t, err, "error creating dir %s", fullTrueSubdir)
		err = m.WriteFile(truefile, content, 0o644)
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

func TestMemFSXattrs(t *testing.T) {
	t.Run("file not exist", func(t *testing.T) {
		var (
			m = NewMemFS()
		)
		err := m.SetXattr("/a/b", "user.foo", []byte("hello"))
		require.Error(t, err, os.ErrNotExist)
	})
	t.Run("file exist", func(t *testing.T) {
		var (
			m    = NewMemFS()
			dir  = "/a"
			file = "/a/b"
			link = "/a/l"
		)
		err := m.Mkdir(dir, 0o755)
		require.NoError(t, err)
		err = m.WriteFile(file, []byte("hello"), 0o644)
		require.NoError(t, err)
		err = m.Symlink("b", link)
		require.NoError(t, err)

		xattrsTest := func(t *testing.T, m FullFS, target string) {
			var (
				err   error
				data1 = []byte("hello")
				data2 = []byte("world")
				attr1 = "user.foo"
				attr2 = "user.bar"
				val   []byte
			)
			err = m.SetXattr(target, attr1, data1)
			require.NoError(t, err)
			err = m.SetXattr(target, attr2, data2)
			require.NoError(t, err)

			val, err = m.GetXattr(target, attr1)
			require.NoError(t, err)
			require.Equal(t, data1, val)

			val, err = m.GetXattr(target, attr2)
			require.NoError(t, err)
			require.Equal(t, data2, val)

			vals, err := m.ListXattrs(target)
			require.NoError(t, err)
			require.Len(t, vals, 2)
			require.Contains(t, vals, attr1)
			require.Contains(t, vals, attr2)
			require.Equal(t, data1, vals[attr1])
			require.Equal(t, data2, vals[attr2])
		}

		t.Run("on directory", func(t *testing.T) {
			xattrsTest(t, m, dir)
		})
		t.Run("on file", func(t *testing.T) {
			xattrsTest(t, m, file)
		})

		t.Run("on symlink", func(t *testing.T) {
			xattrsTest(t, m, link)
		})
	})
}

func TestMemFSSymlinkLoop(t *testing.T) {
	var (
		m   = NewMemFS()
		err error
	)
	err = m.MkdirAll("/a/b/c", 0o755)
	require.NoError(t, err)
	err = m.Symlink("/a/b", "/a/link")
	require.NoError(t, err)
	err = m.MkdirAll("/a/link/q/c", 0o755)
	require.NoError(t, err)
}

func TestMemFSSymlinkCycle(t *testing.T) {
	var (
		m   = NewMemFS()
		err error
	)
	err = m.MkdirAll("/a", 0o755)
	require.NoError(t, err)
	err = m.Symlink("b", "/a/b")
	require.NoError(t, err)

	// should be able to read the link, even if a cycle
	target, err := m.Readlink("/a/b")
	require.NoError(t, err)
	require.Equal(t, "b", target)

	// but if we try to go into it, we should not get an infinite loop
	_, err = m.ReadDir("/a/b")
	require.Error(t, err)

	// same for treatung it as a file
	_, err = m.ReadFile("/a/b")
	require.Error(t, err)

	// same for Mkdir and MkdirAll
	err = m.Mkdir("/a/b/c", 0o755)
	require.Error(t, err)

	err = m.MkdirAll("/a/b/c/d", 0o755)
	require.Error(t, err)
}

func TestMemFSConsistentOrdering(t *testing.T) {
	var (
		m = NewMemFS()
	)
	entries := []testDirEntry{
		{"dir1", 0o777, true, nil},
		{"dir1/subdir1", 0o777, true, nil},
		{"dir1/subdir1/file1", 0o644, false, nil},
		{"dir1/subdir1/file2", 0o644, false, nil},
		{"dir1/subdir2", 0o777, true, nil},
		{"dir1/subdir2/file1", 0o644, false, nil},
		{"dir1/subdir2/file2", 0o644, false, nil},
		{"dir1/subdir3", 0o777, true, nil},
		{"dir1/subdir3/file1", 0o644, false, nil},
		{"dir1/subdir3/file2", 0o644, false, nil},
		{"dir2", 0o777, true, nil},
		{"dir2/subdir1", 0o777, true, nil},
		{"dir2/subdir1/file1", 0o644, false, nil},
		{"dir2/subdir1/file2", 0o644, false, nil},
		{"dir2/subdir2", 0o777, true, nil},
		{"dir2/subdir2/file1", 0o644, false, nil},
		{"dir2/subdir2/file2", 0o644, false, nil},
		{"dir2/subdir3", 0o777, true, nil},
		{"dir2/subdir3/file1", 0o644, false, nil},
		{"dir2/subdir3/file2", 0o644, false, nil},
		{"dir2/file1", 0o644, false, nil},
		{"dir2/file2", 0o644, false, nil},
		{"dir2/file3", 0o644, false, nil},
	}
	for _, e := range entries {
		var err error
		if e.dir {
			err = m.Mkdir(e.path, e.perms)
		} else {
			err = m.WriteFile(e.path, e.content, e.perms)
		}
		require.NoError(t, err)
	}
	// now walk the tree, we should get consistent results each time
	var results []string
	for i := 0; i < 10; i++ {
		var result []string
		err := fs.WalkDir(m, "/", func(path string, _ fs.DirEntry, err error) error {
			require.NoError(t, err)
			result = append(result, path)
			return nil
		})
		require.NoError(t, err)
		if i == 0 {
			results = result
			continue
		}
		require.Equal(t, results, result, "iteration %d", i)
	}
	// all results should be the same
}
func TestMemFSCreate(t *testing.T) {
	var (
		m   = NewMemFS()
		err error
	)
	fd, err := m.Create("testfile")
	require.NoError(t, err)
	defer fd.Close()

	fileInfo, err := fd.Stat()
	require.NoError(t, err)
	require.Equal(t, fileInfo.Mode(), fs.FileMode(0o644))
}
