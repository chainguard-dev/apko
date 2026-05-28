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
	"io/fs"
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

	type erofsGroupWriter struct {
		path    string
		w       *erofs.Writer
		closer  func() error
		emitted map[string]bool // absPath -> already emitted into this writer
		pkgs    map[string]bool // package names owned by this group
	}

	newWriter := func() (*erofsGroupWriter, error) {
		f, err := newErofsLayerFile(tmpdir, "apko-erofs-*.bin")
		if err != nil {
			return nil, err
		}
		var createOpts []erofs.CreateOpt
		if !buildTime.IsZero() {
			createOpts = append(createOpts, erofs.WithBuildTime(uint64(buildTime.Unix()), uint32(buildTime.Nanosecond())))
		}
		gw := &erofsGroupWriter{
			path:    f.Name(),
			w:       erofs.Create(f, createOpts...),
			emitted: map[string]bool{},
			pkgs:    map[string]bool{},
		}
		// Close the file only after closing the erofs writer (which may seek
		// back to rewrite the superblock).
		gw.closer = func() error {
			if err := gw.w.Close(); err != nil {
				_ = f.Close()
				return fmt.Errorf("finalizing erofs image %s: %w", f.Name(), err)
			}
			return f.Close()
		}
		return gw, nil
	}

	// One writer per group, plus a top writer for entries not owned by any
	// package.
	packageToWriter := map[string]*erofsGroupWriter{}
	groupToWriter := map[*group]*erofsGroupWriter{}
	writers := make([]*erofsGroupWriter, 0, len(groups)+1)

	for _, g := range groups {
		gw, err := newWriter()
		if err != nil {
			return nil, err
		}
		writers = append(writers, gw)
		groupToWriter[g] = gw
		for _, pkg := range g.pkgs {
			packageToWriter[pkg.Name] = gw
			gw.pkgs[pkg.Name] = true
		}
	}
	top, err := newWriter()
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
	emitAncestors := func(gw *erofsGroupWriter, absPath string) error {
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
			if err := emitErofsEntry(gw.w, anc, dirFsysPath[anc], info, fsys, buf); err != nil {
				return fmt.Errorf("emit ancestor %s: %w", anc, err)
			}
			gw.emitted[anc] = true
		}
		return nil
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
			// Record metadata; don't emit yet. Each writer creates this
			// directory lazily the first time it needs to write something
			// beneath it.
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
			dirInfo[absPath] = info
			dirFsysPath[absPath] = fpath
			return nil
		}

		// Default to the top layer.
		owner := top

		// If the file info exposes its owning package, route to that group.
		if pkger, ok := info.Sys().(interface {
			Package() *apk.Package
		}); ok {
			if pkg := pkger.Package(); pkg != nil {
				if gw, ok := packageToWriter[pkg.Name]; ok {
					owner = gw
				}
			}
		}

		// Special-case the apk installed db: each group also gets a partial
		// installed db containing only its own packages, so per-layer
		// scanners (Trivy, Snyk, etc.) can identify the layer's contents.
		// This matches splitLayers' behavior for tar layers.
		if strings.TrimPrefix(absPath, "/") == "usr/lib/apk/db/installed" {
			for _, g := range groups {
				gw := groupToWriter[g]
				if err := emitAncestors(gw, absPath); err != nil {
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

		if err := emitAncestors(owner, absPath); err != nil {
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
		if err := gw.closer(); err != nil {
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
	return layers, nil
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
		if _, err := fout.Write(data); err != nil {
			_ = fout.Close()
			return fmt.Errorf("write %s: %w", absPath, err)
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
