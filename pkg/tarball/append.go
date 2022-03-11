package tarball

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"io/fs"
)

type multi struct {
	buff []func() error
	out  io.Writer
}

func (ctx *Context) Out(dst io.Writer) *multi {
	return &multi{
		out: dst,
	}
}

func (m *multi) Append(ctx *Context, src fs.FS, extra ...io.Writer) *multi {
	dst := io.MultiWriter(append([]io.Writer{m.out}, extra...)...)

	gzw := gzip.NewWriter(dst)
	tw := tar.NewWriter(gzw)

	m.buff = append(m.buff, func() error {
		defer gzw.Flush()
		defer tw.Flush()
		return ctx.writeTar(tw, src)
	})

	return m
}

func (m *multi) Write() error {
	for _, f := range m.buff {
		if err := f(); err != nil {
			return err
		}
	}

	gzw := gzip.NewWriter(m.out)
	defer gzw.Close()

	tw := tar.NewWriter(gzw)
	defer tw.Close()

	return nil
}
