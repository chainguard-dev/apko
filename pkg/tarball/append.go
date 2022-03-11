package tarball

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"io/fs"
)

type multi struct {
	out io.Writer
}

func Out(dst io.Writer) *multi {
	return &multi{
		out: dst,
	}
}

func (m *multi) Append(ctx *Context, src fs.FS, extra ...io.Writer) error {
	dst := io.MultiWriter(append([]io.Writer{m.out}, extra...)...)

	gzw := gzip.NewWriter(dst)
	defer gzw.Flush()

	tw := tar.NewWriter(gzw)
	defer tw.Flush()

	return ctx.writeTar(tw, src)
}

func (m *multi) Close() {
	gzw := gzip.NewWriter(m.out)
	defer gzw.Close()

	tw := tar.NewWriter(gzw)
	defer tw.Close()
}
