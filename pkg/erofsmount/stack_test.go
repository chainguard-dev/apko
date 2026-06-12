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
	"io/fs"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

// nakedFS strips the optional extension interfaces (ReadDirFS, StatFS,
// ReadLinkFS) so we can verify Stack's fallback paths.
type nakedFS struct{ inner fs.FS }

func (n nakedFS) Open(name string) (fs.File, error) { return n.inner.Open(name) }

// readDirNames returns the sorted entry names of "etc" in fsys. Every
// fixture in this file puts its top-level dir at "etc"; the helper exists
// just to keep tests focused on what's *in* etc, not on the wiring.
func readDirNames(t *testing.T, fsys fs.FS) []string {
	t.Helper()
	ents, err := fs.ReadDir(fsys, "etc")
	if err != nil {
		t.Fatalf("ReadDir(etc): %v", err)
	}
	out := make([]string, 0, len(ents))
	for _, e := range ents {
		out = append(out, e.Name())
	}
	slices.Sort(out)
	return out
}

func TestStack_Override_TopWins(t *testing.T) {
	base := fstest.MapFS{
		"etc/hostname": {Data: []byte("base"), Mode: 0o644},
	}
	top := fstest.MapFS{
		"etc/hostname": {Data: []byte("top"), Mode: 0o644},
	}
	s := NewStack(base, top)

	data, err := fs.ReadFile(s, "etc/hostname")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "top" {
		t.Errorf("ReadFile: got %q, want %q", data, "top")
	}
	info, err := fs.Stat(s, "etc/hostname")
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != int64(len("top")) {
		t.Errorf("Stat size: got %d, want %d", info.Size(), len("top"))
	}
}

func TestStack_WhiteoutFile_HidesFromLower(t *testing.T) {
	base := fstest.MapFS{
		"etc/secret": {Data: []byte("oops"), Mode: 0o644},
		"etc/keep":   {Data: []byte("kept"), Mode: 0o644},
	}
	top := fstest.MapFS{
		"etc/.wh.secret": {Data: nil, Mode: 0o644},
	}
	s := NewStack(base, top)

	if _, err := fs.Stat(s, "etc/secret"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Stat etc/secret: got %v, want ErrNotExist", err)
	}
	if _, err := fs.ReadFile(s, "etc/secret"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("ReadFile etc/secret: got %v, want ErrNotExist", err)
	}
	// etc/keep must still be visible.
	if data, err := fs.ReadFile(s, "etc/keep"); err != nil {
		t.Errorf("ReadFile etc/keep: %v", err)
	} else if string(data) != "kept" {
		t.Errorf("ReadFile etc/keep: got %q, want %q", data, "kept")
	}
	// ReadDir of etc must contain "keep" but neither "secret" nor ".wh.secret".
	got := readDirNames(t, s)
	want := []string{"keep"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ReadDir etc: got %v, want %v", got, want)
	}
}

func TestStack_WhiteoutDir_HidesEntireSubtree(t *testing.T) {
	base := fstest.MapFS{
		"opt/legacy/bin/old": {Data: []byte("X"), Mode: 0o755},
		"opt/keep/here":      {Data: []byte("Y"), Mode: 0o644},
	}
	top := fstest.MapFS{
		"opt/.wh.legacy": {Data: nil, Mode: 0o644},
	}
	s := NewStack(base, top)

	if _, err := fs.Stat(s, "opt/legacy"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Stat opt/legacy: got %v, want ErrNotExist", err)
	}
	// Reading a child should also fail (parent is whitedout).
	if _, err := fs.Stat(s, "opt/legacy/bin/old"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Stat opt/legacy/bin/old: got %v, want ErrNotExist", err)
	}
	// Sibling directory must still be present.
	if _, err := fs.Stat(s, "opt/keep"); err != nil {
		t.Errorf("Stat opt/keep: %v", err)
	}
}

func TestStack_OpaqueMarker(t *testing.T) {
	base := fstest.MapFS{
		"etc/foo":   {Data: []byte("foo-base"), Mode: 0o644},
		"etc/bar":   {Data: []byte("bar-base"), Mode: 0o644},
		"etc/sub/x": {Data: []byte("x"), Mode: 0o644},
	}
	top := fstest.MapFS{
		"etc/.wh..wh..opq": {Data: nil, Mode: 0o644},
		"etc/baz":          {Data: []byte("baz-top"), Mode: 0o644},
	}
	s := NewStack(base, top)

	// Top layer's own etc/baz remains visible; lower foo/bar/sub are hidden.
	got := readDirNames(t, s)
	want := []string{"baz"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ReadDir etc with opaque: got %v, want %v", got, want)
	}
	if _, err := fs.Stat(s, "etc/foo"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Stat etc/foo behind opaque: got %v, want ErrNotExist", err)
	}
	if data, err := fs.ReadFile(s, "etc/baz"); err != nil {
		t.Fatal(err)
	} else if string(data) != "baz-top" {
		t.Errorf("etc/baz: got %q, want baz-top", data)
	}
}

func TestStack_WhiteoutEntriesNeverLeak(t *testing.T) {
	top := fstest.MapFS{
		"etc/.wh.gone":     {Data: nil, Mode: 0o644},
		"etc/.wh..wh..opq": {Data: nil, Mode: 0o644},
		"etc/here":         {Data: []byte("X"), Mode: 0o644},
	}
	s := NewStack(top)

	got := readDirNames(t, s)
	want := []string{"here"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestStack_TypeMismatch_TopWins(t *testing.T) {
	base := fstest.MapFS{
		"etc/foo/inner": {Data: []byte("inner"), Mode: 0o644},
	}
	top := fstest.MapFS{
		"etc/foo": {Data: []byte("now-a-file"), Mode: 0o644},
	}
	s := NewStack(base, top)

	info, err := fs.Stat(s, "etc/foo")
	if err != nil {
		t.Fatal(err)
	}
	if info.IsDir() {
		t.Errorf("etc/foo: top is a file but Stack reports a dir")
	}
	if data, err := fs.ReadFile(s, "etc/foo"); err != nil {
		t.Fatal(err)
	} else if string(data) != "now-a-file" {
		t.Errorf("got %q", data)
	}
}

func TestStack_ReadDirUnion(t *testing.T) {
	base := fstest.MapFS{
		"etc/a": {Data: []byte("A"), Mode: 0o644},
		"etc/b": {Data: []byte("B"), Mode: 0o644},
	}
	top := fstest.MapFS{
		"etc/b": {Data: []byte("B-top"), Mode: 0o644}, // override
		"etc/c": {Data: []byte("C"), Mode: 0o644},
	}
	s := NewStack(base, top)

	got := readDirNames(t, s)
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	// b should report the top's content/size, not base's.
	info, err := fs.Stat(s, "etc/b")
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != int64(len("B-top")) {
		t.Errorf("etc/b size: got %d, want %d", info.Size(), len("B-top"))
	}
}

func TestStack_LiveBeatsSameLayerWhiteout(t *testing.T) {
	// A malformed-but-possible layer: both the live entry and its whiteout.
	// The live entry should win.
	base := fstest.MapFS{
		"etc/foo": {Data: []byte("old"), Mode: 0o644},
	}
	top := fstest.MapFS{
		"etc/foo":     {Data: []byte("new"), Mode: 0o644},
		"etc/.wh.foo": {Data: nil, Mode: 0o644},
	}
	s := NewStack(base, top)

	data, err := fs.ReadFile(s, "etc/foo")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new" {
		t.Errorf("got %q, want new", data)
	}
	got := readDirNames(t, s)
	if !reflect.DeepEqual(got, []string{"foo"}) {
		t.Errorf("ReadDir got %v, want [foo]", got)
	}
}

func TestStack_SingleLayer(t *testing.T) {
	only := fstest.MapFS{
		"etc/foo": {Data: []byte("X"), Mode: 0o644},
	}
	s := NewStack(only)
	if data, err := fs.ReadFile(s, "etc/foo"); err != nil {
		t.Fatal(err)
	} else if string(data) != "X" {
		t.Errorf("got %q", data)
	}
}

func TestStack_EmptyStack(t *testing.T) {
	s := NewStack()
	info, err := fs.Stat(s, ".")
	if err != nil {
		t.Fatalf("Stat .: %v", err)
	}
	if !info.IsDir() {
		t.Errorf("root should be a dir")
	}
	if _, err := fs.Stat(s, "anything"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("got %v, want ErrNotExist", err)
	}
}

func TestStack_FallbackInterfaces(t *testing.T) {
	// Wrap a MapFS to hide ReadDirFS/StatFS/ReadLinkFS. Stack must still
	// produce correct merged output via the generic fs.ReadDir / fs.Stat
	// helpers that fall back to Open+ReadDirFile.
	base := nakedFS{fstest.MapFS{
		"etc/foo": {Data: []byte("BASE"), Mode: 0o644},
	}}
	top := nakedFS{fstest.MapFS{
		"etc/bar": {Data: []byte("TOP"), Mode: 0o644},
	}}
	s := NewStack(base, top)
	got := readDirNames(t, s)
	want := []string{"bar", "foo"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if data, err := fs.ReadFile(s, "etc/foo"); err != nil {
		t.Fatal(err)
	} else if string(data) != "BASE" {
		t.Errorf("got %q", data)
	}
}

func TestStack_Symlink_ReadLinkRoutesToOwningLayer(t *testing.T) {
	base := fstest.MapFS{
		"bin/sh": {Data: []byte("/bin/busybox"), Mode: fs.ModeSymlink | 0o777},
	}
	top := fstest.MapFS{
		"etc/keep": {Data: []byte("X"), Mode: 0o644},
	}
	s := NewStack(base, top)

	target, err := fs.ReadLink(s, "bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	if target != "/bin/busybox" {
		t.Errorf("got %q, want /bin/busybox", target)
	}
}

func TestStack_PathNormalization(t *testing.T) {
	s := NewStack(fstest.MapFS{
		"etc/foo": {Data: []byte("X"), Mode: 0o644},
	})
	// fs.FS implementations must reject invalid paths per fs.ValidPath rules.
	for _, bad := range []string{"/etc/foo", "etc/foo/", "./etc/foo", "../etc/foo"} {
		if _, err := s.Open(bad); err == nil {
			t.Errorf("Open(%q): expected error, got success", bad)
		}
	}
	// "." is the root.
	if _, err := s.Open("."); err != nil {
		t.Errorf("Open(.): %v", err)
	}
}

func TestStack_OpenDirReadDirYieldsMerged(t *testing.T) {
	// Open returns a stackDir for directories; its ReadDir must reflect the
	// merged union, not just the layer that owns the dir metadata.
	base := fstest.MapFS{
		"etc/a": {Data: []byte("A"), Mode: 0o644},
	}
	top := fstest.MapFS{
		"etc/b": {Data: []byte("B"), Mode: 0o644},
	}
	s := NewStack(base, top)
	f, err := s.Open("etc")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rd, ok := f.(fs.ReadDirFile)
	if !ok {
		t.Fatal("dir handle should implement fs.ReadDirFile")
	}
	ents, err := rd.ReadDir(-1)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		names = append(names, e.Name())
	}
	slices.Sort(names)
	if !reflect.DeepEqual(names, []string{"a", "b"}) {
		t.Errorf("got %v, want [a b]", names)
	}
}

func TestStack_WalkDir_PrunesWhiteoutsAndOpaque(t *testing.T) {
	base := fstest.MapFS{
		"etc/hidden": {Data: []byte("H"), Mode: 0o644},
		"etc/kept":   {Data: []byte("K"), Mode: 0o644},
		"opt/old":    {Data: []byte("O"), Mode: 0o644},
		"opt/sub/x":  {Data: []byte("X"), Mode: 0o644},
	}
	top := fstest.MapFS{
		"etc/.wh.hidden":   {Data: nil, Mode: 0o644},
		"opt/.wh..wh..opq": {Data: nil, Mode: 0o644},
		"opt/new":          {Data: []byte("N"), Mode: 0o644},
	}
	s := NewStack(base, top)

	var seen []string
	err := fs.WalkDir(s, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasPrefix(d.Name(), ".wh.") {
			t.Errorf("whiteout entry leaked: %s", p)
		}
		seen = append(seen, p)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		".",
		"etc", "etc/kept",
		"opt", "opt/new",
	}
	slices.Sort(seen)
	slices.Sort(want)
	if !reflect.DeepEqual(seen, want) {
		t.Errorf("walk: got %v\nwant %v", seen, want)
	}
}
