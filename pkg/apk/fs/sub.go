package fs

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"time"
)

type SubFS struct {
	FS   FullFS
	Root string
}

// validatePath checks if the given path, when joined with Root, stays within Root.
// This prevents directory traversal attacks.
func (s *SubFS) validatePath(path string, op string) (string, error) {
	if !fs.ValidPath(path) {
		return "", &fs.PathError{Op: op, Path: path, Err: fs.ErrInvalid}
	}

	// Clean both paths to resolve any .. or . components
	cleanRoot := filepath.Clean(s.Root)
	fullPath := filepath.Clean(filepath.Join(s.Root, path))

	// Ensure the full path is within the root using filepath.Rel
	rel, err := filepath.Rel(cleanRoot, fullPath)
	if err != nil {
		return "", &fs.PathError{Op: op, Path: path, Err: fmt.Errorf("invalid path: %w", err)}
	}

	// Check if the relative path tries to escape the root
	if strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." {
		return "", &fs.PathError{Op: op, Path: path, Err: fmt.Errorf("path traversal attempt detected")}
	}

	return fullPath, nil
}

func (s *SubFS) Open(path string) (fs.File, error) {
	fullPath, err := s.validatePath(path, "open")
	if err != nil {
		return nil, err
	}
	return s.FS.Open(fullPath)
}

func (s *SubFS) OpenReaderAt(path string) (File, error) {
	fullPath, err := s.validatePath(path, "openreaderat")
	if err != nil {
		return nil, err
	}
	return s.FS.OpenReaderAt(fullPath)
}

func (s *SubFS) OpenFile(name string, flag int, perm fs.FileMode) (File, error) {
	fullPath, err := s.validatePath(name, "openfile")
	if err != nil {
		return nil, err
	}
	return s.FS.OpenFile(fullPath, flag, perm)
}
func (s *SubFS) Create(name string) (File, error) {
	fullPath, err := s.validatePath(name, "create")
	if err != nil {
		return nil, err
	}
	return s.FS.Create(fullPath)
}

func (s *SubFS) ReadFile(name string) ([]byte, error) {
	fullPath, err := s.validatePath(name, "readfile")
	if err != nil {
		return nil, err
	}
	return s.FS.ReadFile(fullPath)
}
func (s *SubFS) WriteFile(name string, b []byte, mode fs.FileMode) error {
	fullPath, err := s.validatePath(name, "writefile")
	if err != nil {
		return err
	}
	return s.FS.WriteFile(fullPath, b, mode)
}

func (s *SubFS) Mkdir(path string, perm fs.FileMode) error {
	fullPath, err := s.validatePath(path, "mkdir")
	if err != nil {
		return err
	}
	return s.FS.Mkdir(fullPath, perm)
}
func (s *SubFS) MkdirAll(path string, perm fs.FileMode) error {
	fullPath, err := s.validatePath(path, "mkdirall")
	if err != nil {
		return err
	}
	return s.FS.MkdirAll(fullPath, perm)
}
func (s *SubFS) ReadDir(name string) ([]fs.DirEntry, error) {
	fullPath, err := s.validatePath(name, "readdir")
	if err != nil {
		return nil, err
	}
	return s.FS.ReadDir(fullPath)
}

func (s *SubFS) Stat(path string) (fs.FileInfo, error) {
	fullPath, err := s.validatePath(path, "stat")
	if err != nil {
		return nil, err
	}
	return s.FS.Stat(fullPath)
}
func (s *SubFS) Lstat(path string) (fs.FileInfo, error) {
	fullPath, err := s.validatePath(path, "lstat")
	if err != nil {
		return nil, err
	}
	return s.FS.Lstat(fullPath)
}

func (s *SubFS) Remove(name string) error {
	fullPath, err := s.validatePath(name, "remove")
	if err != nil {
		return err
	}
	return s.FS.Remove(fullPath)
}
func (s *SubFS) Chmod(path string, perm fs.FileMode) error {
	fullPath, err := s.validatePath(path, "chmod")
	if err != nil {
		return err
	}
	return s.FS.Chmod(fullPath, perm)
}
func (s *SubFS) Chown(path string, uid int, gid int) error {
	fullPath, err := s.validatePath(path, "chown")
	if err != nil {
		return err
	}
	return s.FS.Chown(fullPath, uid, gid)
}
func (s *SubFS) Chtimes(path string, atime time.Time, mtime time.Time) error {
	fullPath, err := s.validatePath(path, "chtimes")
	if err != nil {
		return err
	}
	return s.FS.Chtimes(fullPath, atime, mtime)
}

func (s *SubFS) Symlink(oldname, newname string) error {
	return s.FS.Symlink(oldname, newname)
}
func (s *SubFS) Link(oldname, newname string) error {
	return s.FS.Link(oldname, newname)
}
func (s *SubFS) Readlink(name string) (string, error) {
	fullPath, err := s.validatePath(name, "readlink")
	if err != nil {
		return "", err
	}
	return s.FS.Readlink(fullPath)
}

func (s *SubFS) Mknod(path string, mode uint32, dev int) error {
	fullPath, err := s.validatePath(path, "mknod")
	if err != nil {
		return err
	}
	return s.FS.Mknod(fullPath, mode, dev)
}
func (s *SubFS) Readnod(path string) (int, error) {
	fullPath, err := s.validatePath(path, "readnod")
	if err != nil {
		return 0, err
	}
	return s.FS.Readnod(fullPath)
}

func (s *SubFS) SetXattr(path string, attr string, data []byte) error {
	fullPath, err := s.validatePath(path, "setxattr")
	if err != nil {
		return err
	}
	return s.FS.SetXattr(fullPath, attr, data)
}
func (s *SubFS) GetXattr(path string, attr string) ([]byte, error) {
	fullPath, err := s.validatePath(path, "getxattr")
	if err != nil {
		return nil, err
	}
	return s.FS.GetXattr(fullPath, attr)
}

func (s *SubFS) RemoveXattr(path string, attr string) error {
	fullPath, err := s.validatePath(path, "removexattr")
	if err != nil {
		return err
	}
	return s.FS.RemoveXattr(fullPath, attr)
}

func (s *SubFS) ListXattrs(path string) (map[string][]byte, error) {
	fullPath, err := s.validatePath(path, "listxattrs")
	if err != nil {
		return nil, err
	}
	return s.FS.ListXattrs(fullPath)
}

func (s *SubFS) Sub(path string) (FullFS, error) {
	if path == "." {
		return s, nil
	}

	fullPath, err := s.validatePath(path, "sub")
	if err != nil {
		return nil, err
	}

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
