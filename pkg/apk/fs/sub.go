package fs

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"time"
)

type SubFS struct {
	FS   FullFS
	Root string
}

func (s *SubFS) String() string {
	return fmt.Sprintf("%s:%s", s.FS, s.Root)
}

func (s *SubFS) Open(path string) (fs.File, error) {
	if !fs.ValidPath(path) {
		return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrInvalid}
	}
	fullPath := filepath.Join(s.Root, path)
	return s.FS.Open(fullPath)
}

func (s *SubFS) OpenReaderAt(path string) (File, error) {
	fullPath := filepath.Join(s.Root, path)
	return s.FS.OpenReaderAt(fullPath)
}

func (s *SubFS) OpenFile(name string, flag int, perm fs.FileMode) (File, error) {
	fullPath := filepath.Join(s.Root, name)
	return s.FS.OpenFile(fullPath, flag, perm)
}
func (s *SubFS) Create(name string) (File, error) {
	fullPath := filepath.Join(s.Root, name)
	return s.FS.Create(fullPath)
}

func (s *SubFS) ReadFile(name string) ([]byte, error) {
	fullPath := filepath.Join(s.Root, name)
	return s.FS.ReadFile(fullPath)
}
func (s *SubFS) WriteFile(name string, b []byte, mode fs.FileMode) error {
	fullPath := filepath.Join(s.Root, name)
	return s.FS.WriteFile(fullPath, b, mode)
}

func (s *SubFS) Mkdir(path string, perm fs.FileMode) error {
	fullPath := filepath.Join(s.Root, path)
	return s.FS.Mkdir(fullPath, perm)
}
func (s *SubFS) MkdirAll(path string, perm fs.FileMode) error {
	fullPath := filepath.Join(s.Root, path)
	return s.FS.MkdirAll(fullPath, perm)
}
func (s *SubFS) ReadDir(name string) ([]fs.DirEntry, error) {
	fullPath := filepath.Join(s.Root, name)
	return s.FS.ReadDir(fullPath)
}

func (s *SubFS) Stat(path string) (fs.FileInfo, error) {
	fullPath := filepath.Join(s.Root, path)
	return s.FS.Stat(fullPath)
}
func (s *SubFS) Lstat(path string) (fs.FileInfo, error) {
	fullPath := filepath.Join(s.Root, path)
	return s.FS.Lstat(fullPath)
}

func (s *SubFS) Remove(name string) error {
	fullPath := filepath.Join(s.Root, name)
	return s.FS.Remove(fullPath)
}
func (s *SubFS) Chmod(path string, perm fs.FileMode) error {
	fullPath := filepath.Join(s.Root, path)
	return s.FS.Chmod(fullPath, perm)
}
func (s *SubFS) Chown(path string, uid int, gid int) error {
	fullPath := filepath.Join(s.Root, path)
	return s.FS.Chown(fullPath, uid, gid)
}
func (s *SubFS) Chtimes(path string, atime time.Time, mtime time.Time) error {
	fullPath := filepath.Join(s.Root, path)
	return s.FS.Chtimes(fullPath, atime, mtime)
}

func (s *SubFS) Symlink(oldname, newname string) error {
	return s.FS.Symlink(oldname, newname)
}
func (s *SubFS) Link(oldname, newname string) error {
	return s.FS.Link(oldname, newname)
}
func (s *SubFS) Readlink(name string) (string, error) {
	fullPath := filepath.Join(s.Root, name)
	return s.FS.Readlink(fullPath)
}

func (s *SubFS) Mknod(path string, mode uint32, dev int) error {
	fullPath := filepath.Join(s.Root, path)
	return s.FS.Mknod(fullPath, mode, dev)
}
func (s *SubFS) Readnod(path string) (int, error) {
	fullPath := filepath.Join(s.Root, path)
	return s.FS.Readnod(fullPath)
}

func (s *SubFS) SetXattr(path string, attr string, data []byte) error {
	fullPath := filepath.Join(s.Root, path)
	return s.FS.SetXattr(fullPath, attr, data)
}
func (s *SubFS) GetXattr(path string, attr string) ([]byte, error) {
	fullPath := filepath.Join(s.Root, path)
	return s.FS.GetXattr(fullPath, attr)
}

func (s *SubFS) RemoveXattr(path string, attr string) error {
	fullPath := filepath.Join(s.Root, path)
	return s.FS.RemoveXattr(fullPath, attr)
}

func (s *SubFS) ListXattrs(path string) (map[string][]byte, error) {
	fullPath := filepath.Join(s.Root, path)
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
