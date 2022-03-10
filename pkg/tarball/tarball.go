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
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

type Context struct {
	SourceDateEpoch time.Time
	OverrideUIDGID  bool
	UID             int
	GID             int
	OverrideUname   string
	OverrideGname   string
	SkipClose       bool
}

type Option func(*Context) error

// Generates a new context from a set of options.
func NewContext(opts ...Option) (*Context, error) {
	ctx := Context{}

	for _, opt := range opts {
		if err := opt(&ctx); err != nil {
			return nil, err
		}
	}

	return &ctx, nil
}

// Sets SourceDateEpoch for Context.
func WithSourceDateEpoch(t time.Time) Option {
	return func(ctx *Context) error {
		ctx.SourceDateEpoch = t
		return nil
	}
}

// WithOverrideUIDGID sets the UID/GID to override with for Context.
func WithOverrideUIDGID(uid, gid int) Option {
	return func(ctx *Context) error {
		ctx.OverrideUIDGID = true
		ctx.UID = uid
		ctx.GID = gid
		return nil
	}
}

// WithOverrideUname sets the Uname to use with Context.
func WithOverrideUname(uname string) Option {
	return func(ctx *Context) error {
		ctx.OverrideUname = uname
		return nil
	}
}

// WithOverrideGname sets the Gname to use with Context.
func WithOverrideGname(gname string) Option {
	return func(ctx *Context) error {
		ctx.OverrideGname = gname
		return nil
	}
}

// WithSkipClose is used to determine whether the tar stream
// should be closed.  For concatenated tar streams such as APKv2
// containers, only the final tar stream should be closed.
func WithSkipClose(skipClose bool) Option {
	return func(ctx *Context) error {
		ctx.SkipClose = skipClose
		return nil
	}
}

// Writes a raw TAR archive to out, given an fs.FS.
func (ctx *Context) WriteArchiveFromFS(base string, fsys fs.FS, out io.Writer) error {
	gzw := gzip.NewWriter(out)
	defer gzw.Close()

	tw := tar.NewWriter(gzw)
	if !ctx.SkipClose {
		defer tw.Close()
	} else {
		defer tw.Flush()
	}

	if err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		var link string
		if info.Mode()&os.ModeSymlink == os.ModeSymlink {
			// fs.FS does not implement readlink, so we have this hack for now.
			if link, err = os.Readlink(filepath.Join(base, path)); err != nil {
				return err
			}
		}

		header, err := tar.FileInfoHeader(info, link)
		if err != nil {
			return err
		}
		// work around some weirdness, without this we wind up with just the basename
		header.Name = path

		// zero out timestamps for reproducibility
		header.AccessTime = ctx.SourceDateEpoch
		header.ModTime = ctx.SourceDateEpoch
		header.ChangeTime = ctx.SourceDateEpoch

		if ctx.OverrideUIDGID {
			header.Uid = ctx.UID
			header.Gid = ctx.GID
		}

		if ctx.OverrideUname != "" {
			header.Uname = ctx.OverrideUname
		}

		if ctx.OverrideGname != "" {
			header.Gname = ctx.OverrideGname
		}

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		if info.Mode().IsRegular() {
			data, err := fsys.Open(path)
			if err != nil {
				return err
			}

			defer data.Close()

			if _, err := io.Copy(tw, data); err != nil {
				return err
			}
		}

		return nil
	}); err != nil {
		return err
	}

	return nil
}

// Writes a tarball to a temporary file.  Caller's responsibility to
// clean it up when it's done with it.
func (ctx *Context) WriteArchive(src string, w io.Writer) error {
	fs := os.DirFS(src)
	if err := ctx.WriteArchiveFromFS(src, fs, w); err != nil {
		return fmt.Errorf("writing TAR archive failed: %w", err)
	}

	return nil
}
