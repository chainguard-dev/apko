package fs

import (
	"io/fs"
	"os"
	"path/filepath"
)

type rlfs struct {
	base        string
	f           fs.FS
}

func (f *rlfs) Readlink(name string) (string, error) {
	return os.Readlink(filepath.Join(f.base, name))
}

func (f *rlfs) Open(name string) (fs.File, error) {
	return f.Open(name)
}

func (f *rlfs) Stat(name string) (fs.FileInfo, error) {
	return f.Stat(name)
}
