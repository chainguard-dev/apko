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

package erofsmount

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"text/tabwriter"

	erofs "github.com/erofs/go-erofs"

	"github.com/chainguard-dev/clog"
)

// Ls produces a `tar tvf`-style listing of every entry in src. It opens each
// EROFS layer blob directly via go-erofs, presents the layers as a single
// merged view via Stack, walks that view, and prints each entry to w.
//
// Ls does not mount anything and is cross-platform — it works wherever
// go-erofs builds, regardless of kernel features.
//
// The opts.Mode, opts.Arch, and opts.ReadOnly fields are inherited from the
// Mount API for shape parity; only Arch is meaningful here (used to pick a
// manifest from a multi-arch OCI index).
func Ls(ctx context.Context, src Source, opts Options, w io.Writer) error {
	log := clog.FromContext(ctx)

	layers, cleanup, err := OpenLayers(src, opts.Arch)
	if err != nil {
		return fmt.Errorf("open layers: %w", err)
	}
	defer func() {
		if cerr := cleanup(); cerr != nil {
			log.Warnf("close layer blobs: %v", cerr)
		}
	}()

	stack := NewStack(layers...)
	return walkAndPrint(ctx, stack, w)
}

// walkAndPrint walks fsys and writes one line per entry to w in a format
// similar to `tar tvf`: mode  uid/gid  size  yyyy-mm-dd hh:mm  relpath[ -> target].
func walkAndPrint(ctx context.Context, fsys fs.FS, w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	err := fs.WalkDir(fsys, ".", func(name string, d fs.DirEntry, walkErr error) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if walkErr != nil {
			return walkErr
		}
		if name == "." {
			return nil
		}
		info, err := lstatOn(fsys, name)
		if err != nil {
			return err
		}
		line := formatEntry(fsys, info, name)
		if _, werr := fmt.Fprintln(tw, line); werr != nil {
			return werr
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, erofs.ErrNotImplemented) {
			return fmt.Errorf("walk: this EROFS image uses a feature go-erofs does not yet support (typically compression); use `apko erofs mount` to inspect via the kernel or erofsfuse instead: %w", err)
		}
		return err
	}
	return tw.Flush()
}

// formatEntry renders one entry. uid/gid are pulled from go-erofs's accessor
// interfaces on info.Sys(); they're zero for entries from filesystems that
// don't expose them. Symlink targets come from fs.ReadLinkFS when fsys
// implements it.
func formatEntry(fsys fs.FS, info fs.FileInfo, name string) string {
	uid, gid := uidGidFromSys(info.Sys())
	size := info.Size()
	mt := info.ModTime().UTC().Format("2006-01-02 15:04")

	suffix := ""
	if info.Mode()&fs.ModeSymlink != 0 {
		if rl, ok := fsys.(fs.ReadLinkFS); ok {
			if t, err := rl.ReadLink(name); err == nil {
				suffix = " -> " + t
			}
		}
	}

	return fmt.Sprintf("%s\t%d/%d\t%d\t%s\t%s%s",
		formatMode(info.Mode()), uid, gid, size, mt, name, suffix)
}

// uidGidFromSys extracts numeric ownership from info.Sys() via the
// single-method accessor interfaces that go-erofs documents on its Stat
// type. Anything else (including nil) yields (0, 0).
func uidGidFromSys(sys any) (uint32, uint32) {
	if sys == nil {
		return 0, 0
	}
	type uider interface{ UID() uint32 }
	type gider interface{ GID() uint32 }
	var uid, gid uint32
	if u, ok := sys.(uider); ok {
		uid = u.UID()
	}
	if g, ok := sys.(gider); ok {
		gid = g.GID()
	}
	return uid, gid
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
