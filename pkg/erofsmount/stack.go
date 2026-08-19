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
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"slices"
	"sort"
	"time"
)

// Stack presents N fs.FS layers as a single fs.FS, applying the overlay
// semantics the kernel would apply if the same layers were assembled as
// overlayfs lowerdirs. Layers are stored bottom-up: layers[0] is the base, the
// last element is the topmost. Topmost-wins is the rule for lookups.
//
// Deletions use the overlayfs-native encoding the EROFS image spec mandates
// (§3.6), not the `.wh.` filename convention of OCI tar layers:
//
//   - A whiteout is a character device with rdev 0 (major 0, minor 0). It
//     hides the same-named entry in every lower layer, and is itself absent
//     from the merged view.
//   - An opaque directory is one whose `trusted.overlay.opaque` xattr is "y".
//     It hides all lower-layer children of that directory; entries the opaque
//     layer itself carries remain.
//
// §8.1 item 9 forbids `.wh.`-prefixed names in EROFS images outright, so such
// a name is treated as the literal filename it is — the same thing the kernel
// would do.
//
// Whiteouts are only interpreted when there are at least two layers. A lone
// EROFS layer is mountable directly as a root filesystem (§7 step 6), and in
// that case the kernel never applies overlay semantics, so neither do we: a
// rdev-0 char device in a single-layer image is reported as the device it is.
//
// Stack implements fs.FS, fs.ReadDirFS, fs.StatFS, and fs.ReadLinkFS.
type Stack struct {
	layers []fs.FS
	// whiteouts records whether overlay deletion semantics apply, i.e.
	// whether an overlay stack is assembled at all (§7 Constraints).
	whiteouts bool
}

// NewStack returns a Stack over layers, in bottom-up order (layers[0] is the
// base). Callers that hold layers in OCI manifest order can pass them
// directly; OCI manifest order is also bottom-up.
func NewStack(layers ...fs.FS) *Stack {
	cp := make([]fs.FS, len(layers))
	copy(cp, layers)
	return &Stack{layers: cp, whiteouts: len(cp) > 1}
}

// Open implements fs.FS. For regular files, symlinks, and devices the
// returned fs.File is the topmost layer's view of the entry. For directories
// the returned fs.File is a synthetic fs.ReadDirFile that, on ReadDir, yields
// the merged union of all layer entries with whiteouts applied.
func (s *Stack) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	if name == "." {
		return s.openRoot()
	}
	layer, err := s.lookup(name)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	f, err := s.layers[layer].Open(name)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if info.IsDir() {
		_ = f.Close()
		return s.openDir(name, info)
	}
	return f, nil
}

// Stat implements fs.StatFS.
func (s *Stack) Stat(name string) (fs.FileInfo, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrInvalid}
	}
	if name == "." {
		return s.rootInfo()
	}
	layer, err := s.lookup(name)
	if err != nil {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: err}
	}
	return statOn(s.layers[layer], name)
}

// Lstat implements fs.ReadLinkFS by returning the topmost layer's view of
// the named entry without following symlinks. Without Lstat, fs.ReadLinkFS
// is not satisfied and the package-level fs.ReadLink helper rejects Stack.
func (s *Stack) Lstat(name string) (fs.FileInfo, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "lstat", Path: name, Err: fs.ErrInvalid}
	}
	if name == "." {
		return s.rootInfo()
	}
	layer, err := s.lookup(name)
	if err != nil {
		return nil, &fs.PathError{Op: "lstat", Path: name, Err: err}
	}
	return lstatOn(s.layers[layer], name)
}

// ReadDir implements fs.ReadDirFS, merging entries from every layer that
// contributes to the directory.
func (s *Stack) ReadDir(name string) ([]fs.DirEntry, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrInvalid}
	}
	if name != "." {
		// Confirm the directory exists (not whitedout) in some layer.
		layer, err := s.lookup(name)
		if err != nil {
			return nil, &fs.PathError{Op: "readdir", Path: name, Err: err}
		}
		info, err := statOn(s.layers[layer], name)
		if err != nil {
			return nil, &fs.PathError{Op: "readdir", Path: name, Err: err}
		}
		if !info.IsDir() {
			return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrInvalid}
		}
	}
	return s.mergeDir(name)
}

// ReadLink implements fs.ReadLinkFS.
func (s *Stack) ReadLink(name string) (string, error) {
	if !fs.ValidPath(name) {
		return "", &fs.PathError{Op: "readlink", Path: name, Err: fs.ErrInvalid}
	}
	if name == "." {
		return "", &fs.PathError{Op: "readlink", Path: name, Err: fs.ErrInvalid}
	}
	layer, err := s.lookup(name)
	if err != nil {
		return "", &fs.PathError{Op: "readlink", Path: name, Err: err}
	}
	if rl, ok := s.layers[layer].(fs.ReadLinkFS); ok {
		return rl.ReadLink(name)
	}
	return "", &fs.PathError{Op: "readlink", Path: name, Err: fs.ErrInvalid}
}

// lookup walks layers top-down looking for name. It returns the index of the
// topmost layer that has name live (not whited out). In each layer it asks
// two questions before descending: is name itself a whiteout here, and is
// name's parent directory opaque here?
//
// Ancestors are resolved recursively: if any ancestor of name is whited out,
// opaqued out, or shadowed by a non-directory in a higher layer, name is
// not reachable. The root (".") is always live; lookup(".") returns
// (-1, nil) to signal "root, no owning layer".
func (s *Stack) lookup(name string) (int, error) {
	if name == "." {
		return -1, nil
	}
	parent, base := splitParent(name)

	// Each ancestor must be reachable AND a directory in its owning layer.
	// Without this check, a whiteout or type-shadow on an ancestor wouldn't
	// hide its descendants.
	if parent != "." {
		parentLayer, err := s.lookup(parent)
		if err != nil {
			return -1, err
		}
		if parentLayer >= 0 {
			info, err := statOn(s.layers[parentLayer], parent)
			if err != nil {
				return -1, err
			}
			if !info.IsDir() {
				return -1, fs.ErrNotExist
			}
		}
	}

	for i, layer := range slices.Backward(s.layers) {
		entries, err := readDirOn(layer, parent)
		if err != nil {
			// Parent doesn't exist in this layer; can't hold a whiteout or
			// the entry. Move down.
			continue
		}
		for _, e := range entries {
			if e.Name() != base {
				continue
			}
			white, err := s.isWhiteout(e)
			if err != nil {
				return -1, err
			}
			if white {
				// A whiteout hides every lower layer's entry, and is not
				// itself part of the merged view.
				return -1, fs.ErrNotExist
			}
			return i, nil
		}
		// Not in this layer. If this layer's copy of the parent directory is
		// opaque, it hides everything below.
		opaque, err := s.isOpaqueDir(layer, parent)
		if err != nil {
			return -1, err
		}
		if opaque {
			return -1, fs.ErrNotExist
		}
	}
	return -1, fs.ErrNotExist
}

// mergeDir produces the union of name's entries across layers, top-down,
// applying whiteouts and stopping below the first opaque directory.
//
// A whiteout occupies the name it deletes, so one pass suffices: recording the
// name as seen both suppresses the whiteout itself and shadows every lower
// layer's entry of that name.
func (s *Stack) mergeDir(name string) ([]fs.DirEntry, error) {
	seen := map[string]bool{} // live entries returned so far + tombstones
	var out []fs.DirEntry
	for _, layer := range slices.Backward(s.layers) {
		entries, err := readDirOn(layer, name)
		if err != nil {
			continue
		}
		for _, e := range entries {
			n := e.Name()
			if seen[n] {
				continue
			}
			seen[n] = true
			white, err := s.isWhiteout(e)
			if err != nil {
				return nil, err
			}
			if white {
				continue // tombstone: shadows lower layers, never listed
			}
			out = append(out, e)
		}
		// This layer's own entries are already in; an opaque directory hides
		// only what lies below it.
		opaque, err := s.isOpaqueDir(layer, name)
		if err != nil {
			return nil, err
		}
		if opaque {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, nil
}

// isWhiteout reports whether e is an overlayfs whiteout: a character device
// with rdev 0 (major 0, minor 0), per spec §3.6. It returns false for every
// entry when the stack has no overlay to apply.
//
// The cheap Type() check comes first so the common case costs nothing: only a
// char device is worth an Info() call, which for a real EROFS layer reads the
// inode. That call's failure is reported rather than swallowed, for the same
// reason as isOpaqueDir: whether the entry is a tombstone decides what the
// merged view shows, and answering it from an inode we could not read is a
// guess either way.
func (s *Stack) isWhiteout(e fs.DirEntry) (bool, error) {
	if !s.whiteouts || e.Type()&fs.ModeCharDevice == 0 {
		return false, nil
	}
	info, err := e.Info()
	if err != nil {
		return false, fmt.Errorf("stat %s to check for whiteout: %w", e.Name(), err)
	}
	// go-erofs advertises Rdev() on the FileInfo it returns; an fs.FS with no
	// notion of device numbers cannot express a whiteout at all.
	rd, ok := info.(interface{ Rdev() uint64 })
	return ok && rd.Rdev() == 0, nil
}

// isOpaqueDir reports whether fsys's copy of dir is an opaque directory --
// `trusted.overlay.opaque` set to "y", per spec §3.6 -- which hides every
// lower layer's children of that directory.
//
// A stat failure is reported, not swallowed: opacity hides content, so
// answering "not opaque" for a layer we could not read would silently un-hide
// whatever the image meant to hide. dir being absent from this layer is the one
// benign case, and means exactly "not opaque here".
func (s *Stack) isOpaqueDir(fsys fs.FS, dir string) (bool, error) {
	if !s.whiteouts {
		return false, nil
	}
	info, err := statOn(fsys, dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("stat %s to check for %s: %w", dir, overlayOpaqueXattr, err)
	}
	if !info.IsDir() {
		return false, nil
	}
	gx, ok := info.(interface {
		GetXattr(string) (string, bool)
	})
	if !ok {
		return false, nil
	}
	v, _ := gx.GetXattr(overlayOpaqueXattr)
	return v == "y", nil
}

// rootInfo returns FileInfo for ".". The topmost layer that has a root wins
// for metadata.
func (s *Stack) rootInfo() (fs.FileInfo, error) {
	for _, layer := range slices.Backward(s.layers) {
		if info, err := statOn(layer, "."); err == nil {
			return info, nil
		}
	}
	if len(s.layers) == 0 {
		return syntheticDirInfo(".", time.Time{}), nil
	}
	return nil, &fs.PathError{Op: "stat", Path: ".", Err: fs.ErrNotExist}
}

func (s *Stack) openRoot() (fs.File, error) {
	info, err := s.rootInfo()
	if err != nil {
		return nil, err
	}
	return s.openDir(".", info)
}

func (s *Stack) openDir(name string, info fs.FileInfo) (fs.File, error) {
	entries, err := s.mergeDir(name)
	if err != nil {
		return nil, err
	}
	return &stackDir{name: name, info: info, entries: entries}, nil
}

// stackDir is a synthetic fs.ReadDirFile for a merged directory view.
type stackDir struct {
	name    string
	info    fs.FileInfo
	entries []fs.DirEntry
	pos     int
}

func (d *stackDir) Stat() (fs.FileInfo, error) { return d.info, nil }
func (d *stackDir) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.name, Err: fs.ErrInvalid}
}
func (d *stackDir) Close() error { return nil }

func (d *stackDir) ReadDir(n int) ([]fs.DirEntry, error) {
	remaining := len(d.entries) - d.pos
	if remaining == 0 {
		if n <= 0 {
			return nil, nil
		}
		return nil, io.EOF
	}
	if n <= 0 || n > remaining {
		n = remaining
	}
	out := d.entries[d.pos : d.pos+n]
	d.pos += n
	return out, nil
}

// readDirOn calls ReadDirFS if implemented, else falls back to the helper
// that wraps Open+ReadDirFile.
func readDirOn(fsys fs.FS, name string) ([]fs.DirEntry, error) {
	if rd, ok := fsys.(fs.ReadDirFS); ok {
		return rd.ReadDir(name)
	}
	return fs.ReadDir(fsys, name)
}

// statOn calls StatFS if implemented, else falls back to Open+Stat.
func statOn(fsys fs.FS, name string) (fs.FileInfo, error) {
	if st, ok := fsys.(fs.StatFS); ok {
		return st.Stat(name)
	}
	return fs.Stat(fsys, name)
}

// lstatOn calls ReadLinkFS.Lstat if implemented, else falls back to statOn
// (which is correct for non-symlink entries; the underlying fs.FS doesn't
// expose any way to inspect a symlink without ReadLinkFS support).
func lstatOn(fsys fs.FS, name string) (fs.FileInfo, error) {
	if rl, ok := fsys.(fs.ReadLinkFS); ok {
		return rl.Lstat(name)
	}
	return statOn(fsys, name)
}

// splitParent splits name into (parent-dir, base) using fs.FS path
// conventions. For name=="." the result is (".", ".").
func splitParent(name string) (parent, base string) {
	clean := path.Clean(name)
	if clean == "." || clean == "/" {
		return ".", "."
	}
	parent = path.Dir(clean)
	base = path.Base(clean)
	if parent == "" || parent == "/" {
		parent = "."
	}
	return parent, base
}

// overlayOpaqueXattr is the extended attribute the kernel's overlayfs uses to
// mark a directory as hiding all lower-layer children. Spec §3.6 adopts it
// verbatim.
const overlayOpaqueXattr = "trusted.overlay.opaque"

// syntheticDirInfo produces a minimal fs.FileInfo for a synthetic directory
// (used only when Stack has zero layers, so callers don't crash).
func syntheticDirInfo(name string, mt time.Time) fs.FileInfo {
	return &synthInfo{name: name, mode: fs.ModeDir | 0o555, mtime: mt}
}

type synthInfo struct {
	name  string
	mode  fs.FileMode
	mtime time.Time
}

func (i *synthInfo) Name() string       { return i.name }
func (i *synthInfo) Size() int64        { return 0 }
func (i *synthInfo) Mode() fs.FileMode  { return i.mode }
func (i *synthInfo) ModTime() time.Time { return i.mtime }
func (i *synthInfo) IsDir() bool        { return i.mode.IsDir() }
func (i *synthInfo) Sys() any           { return nil }
