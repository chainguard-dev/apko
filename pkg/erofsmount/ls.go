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
	"strconv"
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

// formatEntry renders one entry. Mode, ownership and device numbers come from
// the *erofs.Stat on info.Sys() when present: fs.FileInfo.Mode() alone reports
// raw on-disk bits and no setuid/setgid/sticky, and fs.FileInfo has nowhere to
// put a uid. Entries without one (synthesized parent directories) fall back to
// the plain FileInfo and show 0/0. Symlink targets come from fs.ReadLinkFS
// when fsys implements it.
func formatEntry(fsys fs.FS, info fs.FileInfo, name string) string {
	mode := info.Mode()
	var uid, gid, rdev uint32
	if st, ok := info.Sys().(*erofs.Stat); ok {
		mode, uid, gid, rdev = st.Mode, st.UID, st.GID, st.Rdev
	}

	// Devices have no meaningful length; `tar tv` puts major,minor here.
	sizeCol := strconv.FormatInt(info.Size(), 10)
	if mode&(fs.ModeDevice|fs.ModeCharDevice) != 0 {
		major, minor := decodeRdev(rdev)
		sizeCol = fmt.Sprintf("%d,%d", major, minor)
	}

	mt := info.ModTime().UTC().Format("2006-01-02 15:04")

	suffix := ""
	if mode&fs.ModeSymlink != 0 {
		if rl, ok := fsys.(fs.ReadLinkFS); ok {
			if t, err := rl.ReadLink(name); err == nil {
				suffix = " -> " + t
			}
		}
	}

	return fmt.Sprintf("%s\t%d/%d\t%s\t%s\t%s%s",
		formatMode(mode), uid, gid, sizeCol, mt, name, suffix)
}

// decodeRdev splits a device number as stored in an EROFS inode into major and
// minor. EROFS records what Linux's new_encode_dev() produced, so decode it the
// same way rather than with unix.Major/Minor, whose encoding is host-specific.
func decodeRdev(rdev uint32) (major, minor uint32) {
	return (rdev & 0xfff00) >> 8, (rdev & 0xff) | ((rdev >> 12) & 0xfff00)
}

// formatMode renders a 10-character mode string in the style of `ls -l`,
// including the setuid/setgid/sticky overloads of the execute columns.
func formatMode(mode fs.FileMode) string {
	out := []byte("----------")
	switch {
	case mode.IsDir():
		out[0] = 'd'
	case mode&fs.ModeSymlink != 0:
		out[0] = 'l'
	case mode&fs.ModeNamedPipe != 0:
		out[0] = 'p'
	case mode&fs.ModeSocket != 0:
		out[0] = 's'
	case mode&fs.ModeCharDevice != 0:
		out[0] = 'c'
	case mode&fs.ModeDevice != 0:
		out[0] = 'b'
	}
	perm := mode.Perm()
	for i, ch := range []byte("rwxrwxrwx") {
		if perm&(1<<(8-i)) != 0 {
			out[i+1] = ch
		}
	}
	// setuid/setgid/sticky take over the matching execute column, upper-case
	// when the execute bit itself is clear.
	for _, s := range []struct {
		bit       fs.FileMode
		col       int
		set, only byte
	}{
		{fs.ModeSetuid, 3, 's', 'S'},
		{fs.ModeSetgid, 6, 's', 'S'},
		{fs.ModeSticky, 9, 't', 'T'},
	} {
		if mode&s.bit == 0 {
			continue
		}
		if out[s.col] == 'x' {
			out[s.col] = s.set
		} else {
			out[s.col] = s.only
		}
	}
	return string(out)
}
