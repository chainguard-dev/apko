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
	"io"
	"io/fs"
	"path"
	"slices"
	"sort"
	"strings"
	"time"
)

// Stack presents N fs.FS layers as a single fs.FS using AUFS-style overlay
// semantics. Layers are stored bottom-up: layers[0] is the base, the last
// element is the topmost. Topmost-wins is the rule for lookups.
//
// Whiteout encoding (matches OCI tar layers and go-erofs Writer.Merge):
//
//   - `.wh.NAME` as a sibling of NAME hides NAME from lower layers.
//   - `.wh..wh..opq` in a directory hides all entries from lower layers in
//     that directory; entries that the same layer also has live remain.
//
// Stack implements fs.FS, fs.ReadDirFS, fs.StatFS, and fs.ReadLinkFS.
type Stack struct {
	layers []fs.FS
}

// NewStack returns a Stack over layers, in bottom-up order (layers[0] is the
// base). Callers that hold layers in OCI manifest order can pass them
// directly; OCI manifest order is also bottom-up.
func NewStack(layers ...fs.FS) *Stack {
	cp := make([]fs.FS, len(layers))
	copy(cp, layers)
	return &Stack{layers: cp}
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
// topmost layer that has name live (not whitedout). It checks the parent
// directory of name in each layer for sibling whiteouts (.wh.NAME) and
// opaque markers (.wh..wh..opq) before descending to lower layers.
//
// Ancestors are resolved recursively: if any ancestor of name is whitedout,
// opaqued out, or shadowed by a non-directory in a higher layer, name is
// not reachable. The root (".") is always live; lookup(".") returns
// (-1, nil) to signal "root, no owning layer".
//
// If a layer contains both name and its whiteout (a malformed but possible
// state), the live entry wins.
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
			// Parent doesn't exist in this layer; can't have a whiteout or
			// the entry. Move down.
			continue
		}
		var foundBase, foundWhiteout, foundOpaque bool
		for _, e := range entries {
			switch e.Name() {
			case base:
				foundBase = true
			case whiteoutPrefix + base:
				foundWhiteout = true
			case opaqueMarker:
				foundOpaque = true
			}
		}
		switch {
		case foundBase:
			return i, nil
		case foundWhiteout, foundOpaque:
			return -1, fs.ErrNotExist
		}
	}
	return -1, fs.ErrNotExist
}

// mergeDir produces the union of name's entries across layers, top-down,
// applying whiteouts and stopping at the first opaque marker. Within a
// single layer, if a name is both live and whitedout, the live entry wins
// and the in-layer whiteout is treated as a no-op (lower layers still see
// the layer's live entry shadowing them).
func (s *Stack) mergeDir(name string) ([]fs.DirEntry, error) {
	seen := map[string]bool{} // covers live entries returned so far + tombstones
	var out []fs.DirEntry
	for _, layer := range slices.Backward(s.layers) {
		entries, err := readDirOn(layer, name)
		if err != nil {
			continue
		}
		var opaqueInThisLayer bool
		liveInThisLayer := map[string]fs.DirEntry{}
		whiteoutInThisLayer := map[string]bool{}
		for _, e := range entries {
			n := e.Name()
			switch {
			case n == opaqueMarker:
				opaqueInThisLayer = true
			case strings.HasPrefix(n, whiteoutPrefix):
				whiteoutInThisLayer[strings.TrimPrefix(n, whiteoutPrefix)] = true
			default:
				liveInThisLayer[n] = e
			}
		}
		// Add this layer's live entries that haven't already been provided
		// by an upper layer.
		for n, e := range liveInThisLayer {
			if !seen[n] {
				seen[n] = true
				out = append(out, e)
			}
		}
		// Apply tombstones from this layer for lower layers. If a name is
		// also live here, the live entry shadows lower layers already.
		for n := range whiteoutInThisLayer {
			if _, live := liveInThisLayer[n]; !live {
				seen[n] = true
			}
		}
		if opaqueInThisLayer {
			break // lower layers' entries are hidden
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, nil
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

const (
	whiteoutPrefix = ".wh."
	opaqueMarker   = ".wh..wh..opq"
)

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
