package fs

import (
	"io/fs"
	"os"
)

type ReadLinkFS interface {
	fs.FS

	Readlink(name string) (string, error)
}

func DirFS(dir string) ReadLinkFS {
	return &rlfs{
		base: dir,
		f:    os.DirFS(dir),
	}
}
