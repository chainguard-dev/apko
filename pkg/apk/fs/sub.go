package fs

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"time"
)

// SubFS presents the directory Root of FS as a filesystem of its own by
// joining Root onto every path argument.
//
// SubFS is a prefix, not a sandbox. A path that would climb above Root
// lexically (a ".." that leaves it) is rejected with fs.ErrInvalid, so a
// caller cannot name a sibling of Root. Symlinks are another matter: FS
// resolves them and knows nothing about Root, so a link under Root whose
// target is absolute, or climbs with "..", is followed to wherever it points
// within FS. Whether that stays inside Root is up to FS. A dirfs confines
// every path to its base directory through os.Root, which is the base as a
// whole, not Root. A memfs does not confine at all. Callers that need a
// boundary against untrusted names must get it from FS, not from SubFS.
type SubFS struct {
	FS   FullFS
	Root string
}

// join resolves name against Root. Leading separators are dropped, so an
// absolute and a relative name mean the same thing, as callers expect. A
// name that would climb above Root is rejected; what the resulting path
// means, including any symlink in it, is for FS to decide.
func (s *SubFS) join(op, name string) (string, error) {
	rel := strings.TrimLeft(name, pathSeparator)
	if rel == "" {
		rel = "."
	}
	if !filepath.IsLocal(rel) {
		return "", &fs.PathError{Op: op, Path: name, Err: fs.ErrInvalid}
	}
	return filepath.Join(s.Root, rel), nil
}

func (s *SubFS) Open(path string) (fs.File, error) {
	if !fs.ValidPath(path) {
		return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrInvalid}
	}
	fullPath := filepath.Join(s.Root, path)
	return s.FS.Open(fullPath)
}

func (s *SubFS) OpenReaderAt(path string) (File, error) {
	fullPath, err := s.join("openreaderat", path)
	if err != nil {
		return nil, err
	}
	return s.FS.OpenReaderAt(fullPath)
}

func (s *SubFS) OpenFile(name string, flag int, perm fs.FileMode) (File, error) {
	fullPath, err := s.join("openfile", name)
	if err != nil {
		return nil, err
	}
	return s.FS.OpenFile(fullPath, flag, perm)
}
func (s *SubFS) Create(name string) (File, error) {
	fullPath, err := s.join("create", name)
	if err != nil {
		return nil, err
	}
	return s.FS.Create(fullPath)
}

func (s *SubFS) ReadFile(name string) ([]byte, error) {
	fullPath, err := s.join("readfile", name)
	if err != nil {
		return nil, err
	}
	return s.FS.ReadFile(fullPath)
}
func (s *SubFS) WriteFile(name string, b []byte, mode fs.FileMode) error {
	fullPath, err := s.join("writefile", name)
	if err != nil {
		return err
	}
	return s.FS.WriteFile(fullPath, b, mode)
}

func (s *SubFS) Mkdir(path string, perm fs.FileMode) error {
	fullPath, err := s.join("mkdir", path)
	if err != nil {
		return err
	}
	return s.FS.Mkdir(fullPath, perm)
}
func (s *SubFS) MkdirAll(path string, perm fs.FileMode) error {
	fullPath, err := s.join("mkdirall", path)
	if err != nil {
		return err
	}
	return s.FS.MkdirAll(fullPath, perm)
}
func (s *SubFS) ReadDir(name string) ([]fs.DirEntry, error) {
	fullPath, err := s.join("readdir", name)
	if err != nil {
		return nil, err
	}
	return s.FS.ReadDir(fullPath)
}

func (s *SubFS) Stat(path string) (fs.FileInfo, error) {
	fullPath, err := s.join("stat", path)
	if err != nil {
		return nil, err
	}
	return s.FS.Stat(fullPath)
}
func (s *SubFS) Lstat(path string) (fs.FileInfo, error) {
	fullPath, err := s.join("lstat", path)
	if err != nil {
		return nil, err
	}
	return s.FS.Lstat(fullPath)
}

func (s *SubFS) Remove(name string) error {
	fullPath, err := s.join("remove", name)
	if err != nil {
		return err
	}
	return s.FS.Remove(fullPath)
}
func (s *SubFS) Chmod(path string, perm fs.FileMode) error {
	fullPath, err := s.join("chmod", path)
	if err != nil {
		return err
	}
	return s.FS.Chmod(fullPath, perm)
}
func (s *SubFS) Chown(path string, uid int, gid int) error {
	fullPath, err := s.join("chown", path)
	if err != nil {
		return err
	}
	return s.FS.Chown(fullPath, uid, gid)
}
func (s *SubFS) Lchown(path string, uid int, gid int) error {
	lfs, ok := s.FS.(LchownFS)
	if !ok {
		return fmt.Errorf("lchown %q: underlying filesystem: %w", path, errors.ErrUnsupported)
	}
	fullPath, err := s.join("lchown", path)
	if err != nil {
		return err
	}
	return lfs.Lchown(fullPath, uid, gid)
}
func (s *SubFS) Chtimes(path string, atime time.Time, mtime time.Time) error {
	fullPath, err := s.join("chtimes", path)
	if err != nil {
		return err
	}
	return s.FS.Chtimes(fullPath, atime, mtime)
}

// Symlink creates newname under the sub-filesystem root. oldname is the
// target string stored in the link, not a path on this filesystem, so it is
// passed through unchanged: a relative target resolves against the link's own
// directory, and an absolute target records exactly what the caller wrote.
func (s *SubFS) Symlink(oldname, newname string) error {
	fullNewname, err := s.join("symlink", newname)
	if err != nil {
		return err
	}
	return s.FS.Symlink(oldname, fullNewname)
}

// Link creates newname as a hard link to oldname. Both are paths on this
// filesystem, so both are resolved under the sub-filesystem root.
func (s *SubFS) Link(oldname, newname string) error {
	fullOldname, err := s.join("link", oldname)
	if err != nil {
		return err
	}
	fullNewname, err := s.join("link", newname)
	if err != nil {
		return err
	}
	return s.FS.Link(fullOldname, fullNewname)
}
func (s *SubFS) Readlink(name string) (string, error) {
	fullPath, err := s.join("readlink", name)
	if err != nil {
		return "", err
	}
	return s.FS.Readlink(fullPath)
}

func (s *SubFS) Mknod(path string, mode uint32, dev int) error {
	fullPath, err := s.join("mknod", path)
	if err != nil {
		return err
	}
	return s.FS.Mknod(fullPath, mode, dev)
}
func (s *SubFS) Readnod(path string) (int, error) {
	fullPath, err := s.join("readnod", path)
	if err != nil {
		return 0, err
	}
	return s.FS.Readnod(fullPath)
}

func (s *SubFS) SetXattr(path string, attr string, data []byte) error {
	fullPath, err := s.join("setxattr", path)
	if err != nil {
		return err
	}
	return s.FS.SetXattr(fullPath, attr, data)
}
func (s *SubFS) GetXattr(path string, attr string) ([]byte, error) {
	fullPath, err := s.join("getxattr", path)
	if err != nil {
		return nil, err
	}
	return s.FS.GetXattr(fullPath, attr)
}

func (s *SubFS) RemoveXattr(path string, attr string) error {
	fullPath, err := s.join("removexattr", path)
	if err != nil {
		return err
	}
	return s.FS.RemoveXattr(fullPath, attr)
}

func (s *SubFS) ListXattrs(path string) (map[string][]byte, error) {
	fullPath, err := s.join("listxattrs", path)
	if err != nil {
		return nil, err
	}
	return s.FS.ListXattrs(fullPath)
}

func (s *SubFS) Sub(path string) (FullFS, error) {
	if !fs.ValidPath(path) {
		return nil, &fs.PathError{Op: "sub", Path: path, Err: fs.ErrInvalid}
	}

	cleanPath := filepath.Clean(path)

	if cleanPath == "." {
		return s, nil
	}

	fullPath := filepath.Join(s.Root, cleanPath)
	info, err := s.FS.Stat(fullPath)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("not a directory")
	}

	return &SubFS{
		FS:   s.FS,
		Root: fullPath,
	}, nil
}
