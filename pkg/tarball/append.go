// Copyright 2022 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tarball

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"io/fs"
)

type MultiTar struct {
	out io.Writer
}

func Out(dst io.Writer) *MultiTar {
	return &MultiTar{
		out: dst,
	}
}

func (m *MultiTar) Append(ctx *Context, src fs.FS, extra ...io.Writer) error {
	dst := io.MultiWriter(append([]io.Writer{m.out}, extra...)...)

	gzw := gzip.NewWriter(dst)
	defer gzw.Flush()

	tw := tar.NewWriter(gzw)
	defer tw.Flush()

	return ctx.writeTar(tw, src)
}

func (m *MultiTar) Close() {
	gzw := gzip.NewWriter(m.out)
	defer gzw.Close()

	tw := tar.NewWriter(gzw)
	defer tw.Close()
}
