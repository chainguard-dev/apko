// Copyright 2026 Chainguard, Inc.
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

//go:build linux

package erofsmount

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/chainguard-dev/clog"
)

// Ls produces a `tar tvf`-style listing of every entry in src. It mounts src
// read-only to a temporary directory, walks the merged view (or the single
// blob mountpoint for KindBlob), prints each entry to w, then unmounts and
// removes the temporary directory.
func Ls(ctx context.Context, src Source, opts Options, w io.Writer) (retErr error) {
	log := clog.FromContext(ctx)
	tmp, err := os.MkdirTemp("", "apko-erofs-ls-*")
	if err != nil {
		return fmt.Errorf("mkdir tmp: %w", err)
	}
	defer func() {
		if rmErr := os.RemoveAll(tmp); rmErr != nil {
			log.Warnf("remove tmp %s: %v", tmp, rmErr)
		}
	}()

	opts.ReadOnly = true
	if _, err := Mount(ctx, src, tmp, opts); err != nil {
		return err
	}
	defer func() {
		if uerr := Unmount(ctx, tmp); uerr != nil {
			if retErr == nil {
				retErr = fmt.Errorf("unmount after ls: %w", uerr)
			} else {
				log.Warnf("unmount after ls error: %v", uerr)
			}
		}
	}()

	root := tmp
	if src.Kind == KindOCIDir {
		root = filepath.Join(tmp, "merged")
	}

	return walkAndPrint(ctx, root, w)
}

// walkAndPrint walks root and writes one line per entry to w in a format
// similar to `tar tvf`: mode  uid/gid  size  yyyy-mm-dd hh:mm  relpath[ -> target].
func walkAndPrint(ctx context.Context, root string, w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	rootClean := filepath.Clean(root)
	err := filepath.WalkDir(rootClean, func(path string, d fs.DirEntry, err error) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if err != nil {
			return err
		}
		// Skip the root itself.
		if path == rootClean {
			return nil
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(rootClean, path)
		if err != nil {
			return err
		}
		line := formatEntry(info, rel, path)
		if _, werr := fmt.Fprintln(tw, line); werr != nil {
			return werr
		}
		return nil
	})
	if err != nil {
		return err
	}
	return tw.Flush()
}

func formatEntry(info fs.FileInfo, rel, path string) string {
	mode := info.Mode()
	modeStr := formatMode(mode)

	var uid, gid int
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		uid = int(st.Uid)
		gid = int(st.Gid)
	}

	size := info.Size()
	mt := info.ModTime().UTC().Format("2006-01-02 15:04")

	suffix := ""
	if mode&fs.ModeSymlink != 0 {
		if target, err := os.Readlink(path); err == nil {
			suffix = " -> " + target
		}
	}

	return fmt.Sprintf("%s\t%d/%d\t%d\t%s\t%s%s", modeStr, uid, gid, size, mt, rel, suffix)
}

// formatMode renders a 10-character mode string in the style of `ls -l`.
func formatMode(mode fs.FileMode) string {
	var b strings.Builder
	b.Grow(10)
	switch {
	case mode.IsDir():
		b.WriteByte('d')
	case mode&fs.ModeSymlink != 0:
		b.WriteByte('l')
	case mode&fs.ModeNamedPipe != 0:
		b.WriteByte('p')
	case mode&fs.ModeSocket != 0:
		b.WriteByte('s')
	case mode&fs.ModeCharDevice != 0:
		b.WriteByte('c')
	case mode&fs.ModeDevice != 0:
		b.WriteByte('b')
	default:
		b.WriteByte('-')
	}
	perm := mode.Perm()
	for i, ch := range "rwxrwxrwx" {
		if perm&(1<<(8-i)) != 0 {
			b.WriteByte(byte(ch))
		} else {
			b.WriteByte('-')
		}
	}
	return b.String()
}
