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

package build

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"time"

	erofs "github.com/erofs/go-erofs"
	v1 "github.com/google/go-containerregistry/pkg/v1"

	"chainguard.dev/apko/pkg/apk/apk"
	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/build/types"
)

// splitErofsLayers is the EROFS analogue of splitLayers. It walks fsys once,
// emitting each entry into the per-package group writer that owns it (or the
// top writer for unowned entries). Each group becomes one EROFS layer tagged
// with role=overlay-lower per the draft erofs/erofs-image-spec §3.8; the top
// (final) layer carries no role per the same rule.
//
// Unlike tar's flat-stream model, EROFS images carry an inode table, so we
// keep per-writer state for which directories have already been emitted and
// only emit each directory once per writer. The fs.WalkDir guarantee that
// ancestors are visited before descendants lets us record directory metadata
// the first time we see it and reuse it when a child needs the ancestor to
// exist in a writer.
func splitErofsLayers(ctx context.Context, fsys apkfs.FullFS, groups []*group, pkgToDiff map[*apk.Package][]byte, tmpdir string, buildTime time.Time) ([]v1.Layer, error) {
	buf := make([]byte, 1<<20)

	// One writer per group, plus a top writer for entries not owned by any
	// package.
	packageToWriter := map[string]*erofsGroupWriter{}
	groupToWriter := map[*group]*erofsGroupWriter{}
	writers := make([]*erofsGroupWriter, 0, len(groups)+1)

	// Nothing here is usable half-built: a caller that gets an error gets no
	// layers, so every writer opened along the way has to be released and its
	// temp file removed. Library callers have no MkdirTemp/RemoveAll wrapper
	// around this the way the CLI does, and each writer holds an unlinked
	// spool fd besides.
	done := false
	defer func() {
		if done {
			return
		}
		for _, gw := range writers {
			gw.discard()
		}
	}()

	for _, g := range groups {
		gw, err := newErofsGroupWriter(tmpdir, buildTime)
		if err != nil {
			return nil, err
		}
		writers = append(writers, gw)
		groupToWriter[g] = gw
		for _, pkg := range g.pkgs {
			packageToWriter[pkg.Name] = gw
		}
	}
	top, err := newErofsGroupWriter(tmpdir, buildTime)
	if err != nil {
		return nil, err
	}
	writers = append(writers, top)

	// Record dir metadata as we go so we can recreate ancestors in any
	// writer that needs them. Keyed by the absolute (writer-side) path.
	dirInfo := map[string]fs.FileInfo{}
	dirFsysPath := map[string]string{} // absPath -> source path (for xattr lookup)

	// emitAncestors makes sure every ancestor of absPath (excluding "/" and
	// absPath itself) has been created in gw with the correct metadata.
	//
	// modTime is the mtime of the entry the ancestors are being created for,
	// and it overrides each ancestor's own. splitLayers does the same for the
	// directories alignStacks replicates, and for the same reason: several
	// packages usually share a directory, only one of their mtimes survives
	// into the merged view, and copying that winner into a group layer makes
	// the layer's bytes -- and so its digest -- depend on packages outside the
	// group. The owning layer still carries the faithful mtime, and it is the
	// one that wins on merge, so nothing observable changes. SOURCE_DATE_EPOCH
	// does not cover this: it seeds the superblock, scripts.tar, the installed
	// db and the config, not per-entry mtimes.
	emitAncestors := func(gw *erofsGroupWriter, absPath string, modTime time.Time) error {
		if absPath == "/" {
			return nil
		}
		// Build the list of ancestor paths from shallowest to deepest.
		var parts []string
		p := path.Dir(absPath)
		for p != "/" && p != "." {
			parts = append([]string{p}, parts...)
			p = path.Dir(p)
		}
		for _, anc := range parts {
			if gw.emitted[anc] {
				continue
			}
			info, ok := dirInfo[anc]
			if !ok {
				// Defensive: should never happen with fs.WalkDir ordering.
				if err := gw.w.Mkdir(anc, 0o755); err != nil {
					return fmt.Errorf("mkdir ancestor %s: %w", anc, err)
				}
				gw.emitted[anc] = true
				continue
			}
			if err := emitErofsEntry(gw.w, anc, dirFsysPath[anc], normalizedModTime{info, modTime}, fsys, buf); err != nil {
				return fmt.Errorf("emit ancestor %s: %w", anc, err)
			}
			gw.emitted[anc] = true
		}
		return nil
	}

	// ownerOf picks the writer an entry belongs in: the group that owns its
	// package, or top for anything unowned.
	//
	// The assertion is on the FileInfo itself, not on info.Sys(). pkg/tarfs --
	// what a real build walks -- hangs Package() off its FileInfo and returns a
	// fresh *tar.Header from Sys(), which has no Package method, so asserting
	// on Sys() routes every file to top. splitLayers asserts on the same
	// receiver this does.
	ownerOf := func(info fs.FileInfo, fpath string) (*erofsGroupWriter, error) {
		pkger, ok := info.(interface {
			Package() *apk.Package
		})
		if !ok {
			return top, nil
		}
		pkg := pkger.Package()
		if pkg == nil {
			return top, nil
		}
		gw, ok := packageToWriter[pkg.Name]
		if !ok {
			// splitLayers panics on this; either way it has to be loud.
			// Falling back to top would hide a grouping bug behind an image
			// that looks fine and is laid out wrong.
			return nil, fmt.Errorf("no layer for package %q, which owns %s", pkg.Name, fpath)
		}
		return gw, nil
	}

	if err := fs.WalkDir(fsys, ".", func(fpath string, d fs.DirEntry, err error) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if err != nil {
			return err
		}

		absPath := erofsAbsPath(fpath)
		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("stat %s: %w", fpath, err)
		}

		if d.IsDir() {
			if absPath == "/" {
				// The root of every EROFS image exists implicitly; still set
				// its metadata across all writers (so uid/gid/xattrs match
				// the source rootfs).
				for _, gw := range writers {
					if err := emitErofsEntry(gw.w, absPath, fpath, info, fsys, buf); err != nil {
						return err
					}
					gw.emitted[absPath] = true
				}
				return nil
			}
			// Record the metadata so any other writer that needs this
			// directory as an ancestor can recreate it faithfully.
			dirInfo[absPath] = info
			dirFsysPath[absPath] = fpath

			// Then emit it into its own owner right away. Leaving it to
			// emitAncestors, which only runs for non-directory entries, drops
			// every directory whose subtree holds no file at all -- /tmp,
			// /run, /var/empty, every mount point -- from all layers, and so
			// from the merged view. writeErofs and splitLayers both write
			// every directory they walk.
			owner, err := ownerOf(info, fpath)
			if err != nil {
				return err
			}
			if err := emitAncestors(owner, absPath, info.ModTime()); err != nil {
				return err
			}
			if owner.emitted[absPath] {
				return nil
			}
			if err := emitErofsEntry(owner.w, absPath, fpath, info, fsys, buf); err != nil {
				return err
			}
			owner.emitted[absPath] = true
			return nil
		}

		owner, err := ownerOf(info, fpath)
		if err != nil {
			return err
		}

		// Special-case the apk installed db: each group also gets a partial
		// installed db containing only its own packages, so per-layer
		// scanners (Trivy, Snyk, etc.) can identify the layer's contents.
		// This matches splitLayers' behavior for tar layers.
		if strings.TrimPrefix(absPath, "/") == "usr/lib/apk/db/installed" {
			for _, g := range groups {
				gw := groupToWriter[g]
				if err := emitAncestors(gw, absPath, info.ModTime()); err != nil {
					return err
				}
				var idb bytes.Buffer
				for _, pkg := range g.pkgs {
					if _, err := idb.Write(pkgToDiff[pkg]); err != nil {
						return err
					}
				}
				if err := writeErofsRegularBytes(gw.w, absPath, info, idb.Bytes()); err != nil {
					return err
				}
				gw.emitted[absPath] = true
			}
			// The top layer also gets the full installed db via the normal
			// path below.
		}

		if err := emitAncestors(owner, absPath, info.ModTime()); err != nil {
			return err
		}
		if err := emitErofsEntry(owner.w, absPath, fpath, info, fsys, buf); err != nil {
			return err
		}
		owner.emitted[absPath] = true
		return nil
	}); err != nil {
		return nil, err
	}

	// Finalize each writer and produce v1.Layer values.
	layers := make([]v1.Layer, 0, len(writers))
	for i, gw := range writers {
		if err := gw.finish(); err != nil {
			return nil, err
		}
		// All layers except the final (top) carry role=overlay-lower per
		// spec §3.8 rule 1. The final layer carries no role.
		var anns map[string]string
		if i < len(writers)-1 {
			anns = map[string]string{types.ErofsRoleAnnotation: types.ErofsRoleOverlayLower}
		}
		l, err := buildErofsLayerFromFile(gw.path, anns)
		if err != nil {
			return nil, fmt.Errorf("finalizing erofs layer %d: %w", i, err)
		}
		layers = append(layers, l)
	}
	done = true
	return layers, nil
}

// normalizedModTime is a FileInfo with its ModTime replaced. Sys() is
// forwarded, so uid/gid still come from the source *tar.Header.
type normalizedModTime struct {
	fs.FileInfo
	mtime time.Time
}

func (n normalizedModTime) ModTime() time.Time { return n.mtime }

// erofsGroupWriter is one output layer under construction: a go-erofs Writer
// over a temp file, plus the set of paths already written into it.
type erofsGroupWriter struct {
	path    string
	file    *os.File
	w       *erofs.Writer
	emitted map[string]bool // absPath -> already emitted into this writer
	closed  bool
}

func newErofsGroupWriter(tmpdir string, buildTime time.Time) (*erofsGroupWriter, error) {
	f, err := newErofsLayerFile(tmpdir, "apko-erofs-*.bin")
	if err != nil {
		return nil, err
	}
	// Always pass the build time, exactly as writeErofs does: omitting it
	// makes go-erofs stamp time.Now() into the superblock from Close, so a
	// caller who left the timestamp zero would get different layer digests on
	// every build. See erofsBuildTime for the clamp.
	sec, nsec := erofsBuildTime(buildTime)
	return &erofsGroupWriter{
		path:    f.Name(),
		file:    f,
		w:       erofs.Create(f, erofs.WithBuildTime(sec, nsec)),
		emitted: map[string]bool{},
	}, nil
}

// finish serializes the image and closes the temp file, which stays on disk
// for the v1.Layer to read back. The erofs writer is closed first: it seeks
// back to rewrite the superblock.
func (gw *erofsGroupWriter) finish() error {
	gw.closed = true
	if err := gw.w.Close(); err != nil {
		_ = gw.file.Close()
		return fmt.Errorf("finalizing erofs image %s: %w", gw.path, err)
	}
	return gw.file.Close()
}

// discard releases everything gw holds and removes its temp file. It is safe
// to call on a writer that has already been finished, and safe to call twice.
//
// go-erofs offers no abort: Writer.Close is the only thing that releases the
// unlinked spool fd holding the file data, and it writes the whole image out
// as a side effect. So the image gets written and then thrown away, which
// costs some IO on a path that is already failing.
func (gw *erofsGroupWriter) discard() {
	if !gw.closed {
		gw.closed = true
		_ = gw.w.Close()
		_ = gw.file.Close()
	}
	_ = os.Remove(gw.path)
}

// writeErofsRegularBytes writes a regular file with the given content into w
// at absPath, copying mode/uid/gid/mtime from info. xattrs are *not* copied
// because the per-group installed db is a synthesized payload, not a
// faithful copy of the source file.
func writeErofsRegularBytes(w *erofs.Writer, absPath string, info fs.FileInfo, data []byte) error {
	fout, err := w.Create(absPath)
	if err != nil {
		return fmt.Errorf("create %s: %w", absPath, err)
	}
	if len(data) > 0 {
		n, err := fout.Write(data)
		if err != nil {
			_ = fout.Close()
			return fmt.Errorf("write %s: %w", absPath, err)
		}
		if n != len(data) {
			_ = fout.Close()
			return fmt.Errorf("write %s: %w (wrote %d of %d bytes)", absPath, io.ErrShortWrite, n, len(data))
		}
	}
	if err := fout.Close(); err != nil {
		return fmt.Errorf("close %s: %w", absPath, err)
	}
	if err := w.Chmod(absPath, info.Mode().Perm()); err != nil {
		return fmt.Errorf("chmod %s: %w", absPath, err)
	}
	uid, gid := uidGidFromInfo(info)
	if err := w.Chown(absPath, uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", absPath, err)
	}
	if mt := info.ModTime(); !mt.IsZero() {
		if err := w.Chtimes(absPath, time.Time{}, mt); err != nil {
			return fmt.Errorf("chtimes %s: %w", absPath, err)
		}
	}
	return nil
}
