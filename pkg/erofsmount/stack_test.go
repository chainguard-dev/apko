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
	"path"
	"reflect"
	"slices"
	"testing"
	"testing/fstest"

	erofs "github.com/erofs/go-erofs"
	"golang.org/x/sys/unix"
)

// nakedFS strips the optional extension interfaces (ReadDirFS, StatFS,
// ReadLinkFS) so we can verify Stack's fallback paths.
type nakedFS struct{ inner fs.FS }

func (n nakedFS) Open(name string) (fs.File, error) { return n.inner.Open(name) }

// overlayFS expresses the two things a spec-conformant EROFS whiteout needs
// and fstest.MapFS cannot represent: a device number and an extended
// attribute. The FileInfo values it hands back implement the same accessor
// interfaces go-erofs advertises on its own FileInfo (Rdev, GetXattr), which
// is what Stack probes -- so a fixture here and a real EROFS layer exercise
// the identical code path. TestStack_Whiteouts_RealErofsLayers checks that
// equivalence against images written by go-erofs.
//
// A whiteout is a MapFS entry with Mode fs.ModeCharDevice and no rdev entry
// (rdev 0). A real device names its rdev explicitly.
type overlayFS struct {
	fstest.MapFS
	rdev   map[string]uint64 // char-device path -> device number; absent means 0
	opaque map[string]bool   // directory paths carrying trusted.overlay.opaque=y
}

func (o overlayFS) wrap(p string, fi fs.FileInfo) fs.FileInfo {
	return &overlayInfo{FileInfo: fi, rdev: o.rdev[p], opaque: o.opaque[p]}
}

func (o overlayFS) Stat(name string) (fs.FileInfo, error) {
	fi, err := o.MapFS.Stat(name)
	if err != nil {
		return nil, err
	}
	return o.wrap(name, fi), nil
}

func (o overlayFS) ReadDir(name string) ([]fs.DirEntry, error) {
	ents, err := o.MapFS.ReadDir(name)
	if err != nil {
		return nil, err
	}
	out := make([]fs.DirEntry, 0, len(ents))
	for _, e := range ents {
		out = append(out, overlayEntry{DirEntry: e, fsys: o, path: path.Join(name, e.Name())})
	}
	return out, nil
}

type overlayEntry struct {
	fs.DirEntry
	fsys overlayFS
	path string
}

func (e overlayEntry) Info() (fs.FileInfo, error) {
	fi, err := e.DirEntry.Info()
	if err != nil {
		return nil, err
	}
	return e.fsys.wrap(e.path, fi), nil
}

type overlayInfo struct {
	fs.FileInfo
	rdev   uint64
	opaque bool
}

func (i *overlayInfo) Rdev() uint64 { return i.rdev }

func (i *overlayInfo) GetXattr(name string) (string, bool) {
	if name == overlayOpaqueXattr && i.opaque {
		return "y", true
	}
	return "", false
}

// whiteout is the MapFile shape of an overlayfs whiteout: a char device whose
// rdev is 0. Pair it with an overlayFS that names no rdev for the path.
func whiteout() *fstest.MapFile {
	return &fstest.MapFile{Mode: fs.ModeCharDevice | fs.ModeDevice | 0o600}
}

// readDirNames returns the sorted entry names of "etc" in fsys. Every
// fixture in this file puts its top-level dir at "etc"; the helper exists
// just to keep tests focused on what's *in* etc, not on the wiring.
func readDirNames(t *testing.T, fsys fs.FS) []string {
	t.Helper()
	return readDirNamesIn(t, fsys, "etc")
}

// readDirNamesIn is readDirNames for a directory other than "etc".
func readDirNamesIn(t *testing.T, fsys fs.FS, dir string) []string {
	t.Helper()
	ents, err := fs.ReadDir(fsys, dir)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", dir, err)
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
	top := overlayFS{MapFS: fstest.MapFS{
		"etc/secret": whiteout(),
	}}
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
	// ReadDir of etc must contain "keep" and not "secret": the whiteout hides
	// the lower entry and is not itself part of the merged view.
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
	top := overlayFS{MapFS: fstest.MapFS{
		"opt/legacy": whiteout(),
	}}
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

func TestStack_OpaqueDir_HidesLowerChildren(t *testing.T) {
	base := fstest.MapFS{
		"etc/foo":   {Data: []byte("foo-base"), Mode: 0o644},
		"etc/bar":   {Data: []byte("bar-base"), Mode: 0o644},
		"etc/sub/x": {Data: []byte("x"), Mode: 0o644},
	}
	top := overlayFS{
		MapFS: fstest.MapFS{
			"etc":     {Mode: fs.ModeDir | 0o755},
			"etc/baz": {Data: []byte("baz-top"), Mode: 0o644},
		},
		opaque: map[string]bool{"etc": true},
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
	base := fstest.MapFS{
		"etc/gone": {Data: []byte("G"), Mode: 0o644},
	}
	top := overlayFS{MapFS: fstest.MapFS{
		"etc/gone": whiteout(),
		"etc/here": {Data: []byte("X"), Mode: 0o644},
	}}
	s := NewStack(base, top)

	got := readDirNames(t, s)
	want := []string{"here"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// A `.wh.`-prefixed name is not a whiteout in an EROFS layer: spec §8.1 item 9
// forbids such names outright, and the kernel would show one as the literal
// filename it is. Stack must do the same rather than reading tar semantics into
// it.
func TestStack_DotWhNames_AreLiteralFilenames(t *testing.T) {
	base := fstest.MapFS{
		"etc/secret": {Data: []byte("S"), Mode: 0o644},
	}
	top := overlayFS{MapFS: fstest.MapFS{
		"etc/.wh.secret":   {Data: nil, Mode: 0o644},
		"etc/.wh..wh..opq": {Data: nil, Mode: 0o644},
	}}
	s := NewStack(base, top)

	got := readDirNames(t, s)
	want := []string{".wh..wh..opq", ".wh.secret", "secret"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ReadDir etc: got %v, want %v", got, want)
	}
	if _, err := fs.Stat(s, "etc/secret"); err != nil {
		t.Errorf("Stat etc/secret: %v; a .wh. name must not hide it", err)
	}
}

// A char device with a real device number is a device, not a tombstone.
func TestStack_RealCharDevice_IsNotWhiteout(t *testing.T) {
	base := fstest.MapFS{
		"dev/null": {Data: []byte("lower"), Mode: 0o644},
	}
	top := overlayFS{
		MapFS: fstest.MapFS{
			"dev/null": {Mode: fs.ModeCharDevice | fs.ModeDevice | 0o666},
		},
		rdev: map[string]uint64{"dev/null": unix.Mkdev(1, 3)},
	}
	s := NewStack(base, top)

	info, err := fs.Stat(s, "dev/null")
	if err != nil {
		t.Fatalf("Stat dev/null: %v; a rdev-nonzero char device is not a whiteout", err)
	}
	if info.Mode()&fs.ModeCharDevice == 0 {
		t.Errorf("dev/null mode %v: want a char device", info.Mode())
	}
	if got := readDirNamesIn(t, s, "dev"); !reflect.DeepEqual(got, []string{"null"}) {
		t.Errorf("ReadDir dev: got %v, want [null]", got)
	}
}

// Spec §7 step 6 lets a lone EROFS layer be mounted directly as a root
// filesystem, and a direct mount applies no overlay semantics. With nothing
// below it to hide, a rdev-0 char device is just a device.
func TestStack_SingleLayer_NoWhiteoutInterpretation(t *testing.T) {
	only := overlayFS{MapFS: fstest.MapFS{
		"etc/odd":  whiteout(),
		"etc/here": {Data: []byte("X"), Mode: 0o644},
	}}
	s := NewStack(only)

	got := readDirNames(t, s)
	want := []string{"here", "odd"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ReadDir etc: got %v, want %v", got, want)
	}
	if _, err := fs.Stat(s, "etc/odd"); err != nil {
		t.Errorf("Stat etc/odd: %v; single-layer stacks apply no whiteouts", err)
	}
}

// TestStack_Whiteouts_RealErofsLayers runs the whiteout rules against images
// go-erofs actually wrote, rather than the overlayFS fixture. It is the check
// that the accessor interfaces Stack probes are the ones a real EROFS layer
// offers: if go-erofs ever stopped reporting Rdev() or GetXattr() on its
// FileInfo, every fixture-based test here would still pass while `apko erofs
// ls` silently stopped hiding anything.
func TestStack_Whiteouts_RealErofsLayers(t *testing.T) {
	base := writeImage(t, func(t *testing.T, w *erofs.Writer) {
		t.Helper()
		for _, dir := range []string{"/etc", "/opt", "/opt/legacy"} {
			if err := w.Mkdir(dir, 0o755); err != nil {
				t.Fatalf("Mkdir(%s): %v", dir, err)
			}
		}
		for _, f := range []string{"/etc/secret", "/etc/keep", "/opt/legacy/old"} {
			fh, err := w.Create(f)
			if err != nil {
				t.Fatalf("Create(%s): %v", f, err)
			}
			if _, err := fh.Write([]byte("lower")); err != nil {
				t.Fatalf("Write(%s): %v", f, err)
			}
			if err := fh.Close(); err != nil {
				t.Fatalf("Close(%s): %v", f, err)
			}
		}
	})

	top := writeImage(t, func(t *testing.T, w *erofs.Writer) {
		t.Helper()
		for _, dir := range []string{"/etc", "/opt"} {
			if err := w.Mkdir(dir, 0o755); err != nil {
				t.Fatalf("Mkdir(%s): %v", dir, err)
			}
		}
		// A whiteout: char device, major 0, minor 0.
		if err := w.Mknod("/etc/secret", unix.S_IFCHR|0o600, 0); err != nil {
			t.Fatalf("Mknod whiteout: %v", err)
		}
		// A real device must survive as a device.
		if err := w.Mknod("/etc/null", unix.S_IFCHR|0o666, uint32(unix.Mkdev(1, 3))); err != nil {
			t.Fatalf("Mknod /etc/null: %v", err)
		}
		// An opaque directory hides /opt/legacy from the lower layer.
		if err := w.Setxattr("/opt", overlayOpaqueXattr, "y"); err != nil {
			t.Fatalf("Setxattr opaque: %v", err)
		}
	})

	s := NewStack(base, top)

	if _, err := fs.Stat(s, "etc/secret"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Stat etc/secret: got %v, want ErrNotExist", err)
	}
	if data, err := fs.ReadFile(s, "etc/keep"); err != nil {
		t.Errorf("ReadFile etc/keep: %v", err)
	} else if string(data) != "lower" {
		t.Errorf("etc/keep: got %q, want lower", data)
	}
	if got := readDirNames(t, s); !reflect.DeepEqual(got, []string{"keep", "null"}) {
		t.Errorf("ReadDir etc: got %v, want [keep null]", got)
	}
	// Opaque /opt hides the lower layer's subtree.
	if _, err := fs.Stat(s, "opt/legacy"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Stat opt/legacy behind opaque dir: got %v, want ErrNotExist", err)
	}
	if got := readDirNamesIn(t, s, "opt"); len(got) != 0 {
		t.Errorf("ReadDir opt: got %v, want empty", got)
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

// A whiteout occupies the very name it deletes, so a layer cannot hold both a
// live entry and its tombstone -- the ambiguity the tar `.wh.` convention
// allows does not exist here. What remains worth pinning is that an opaque
// directory does not hide its own layer's children, only lower ones.
func TestStack_OpaqueDir_KeepsOwnChildren(t *testing.T) {
	base := fstest.MapFS{
		"etc/foo": {Data: []byte("old"), Mode: 0o644},
	}
	top := overlayFS{
		MapFS: fstest.MapFS{
			"etc":     {Mode: fs.ModeDir | 0o755},
			"etc/foo": {Data: []byte("new"), Mode: 0o644},
		},
		opaque: map[string]bool{"etc": true},
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
	top := overlayFS{
		MapFS: fstest.MapFS{
			"etc/hidden": whiteout(),
			"opt":        {Mode: fs.ModeDir | 0o755},
			"opt/new":    {Data: []byte("N"), Mode: 0o644},
		},
		opaque: map[string]bool{"opt": true},
	}
	s := NewStack(base, top)

	var seen []string
	err := fs.WalkDir(s, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeCharDevice != 0 {
			t.Errorf("whiteout entry leaked into the walk: %s", p)
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
