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

package fs

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// subFSBases are the filesystems a SubFS is tested over. onDisk is the
// directory a dirfs base writes to, so tests can check the disk as well as
// the in-memory view; it is empty for memfs.
var subFSBases = map[string]func(t *testing.T) (base FullFS, onDisk string){
	"memfs": func(*testing.T) (FullFS, string) { return NewMemFS(), "" },
	"dirfs": func(t *testing.T) (FullFS, string) {
		dir := t.TempDir()
		return DirFS(t.Context(), dir), dir
	},
}

func TestSubFSSymlinkUnderRoot(t *testing.T) {
	tests := []struct {
		name     string
		target   string // stored verbatim; never resolved by SubFS
		link     string // path given to SubFS
		wantPath string // where the link must land on the base FS
	}{
		{"relative target", "../etc/target", "/home/rel", "/sub/home/rel"},
		{"absolute target", "/etc/target", "/home/abs", "/sub/home/abs"},
		// Tar headers carry relative names.
		{"relative link name", "/etc/target", "home/rel-name", "/sub/home/rel-name"},
	}
	for baseName, newBase := range subFSBases {
		for _, tt := range tests {
			t.Run(baseName+"/"+tt.name, func(t *testing.T) {
				base, onDisk := newBase(t)
				require.NoError(t, base.MkdirAll("/sub/home", 0o755))
				require.NoError(t, base.MkdirAll("/home", 0o755))
				sub := &SubFS{FS: base, Root: "/sub"}

				require.NoError(t, sub.Symlink(tt.target, tt.link))

				// The link lands under the root and stores the target as written.
				got, err := base.Readlink(tt.wantPath)
				require.NoError(t, err)
				require.Equal(t, tt.target, got)

				// Reading back through the SubFS agrees with the base view.
				got, err = sub.Readlink(tt.link)
				require.NoError(t, err)
				require.Equal(t, tt.target, got)

				// Nothing was created at the un-prefixed path outside the root.
				unprefixed := strings.TrimPrefix(tt.wantPath, "/sub")
				_, err = base.Lstat(unprefixed)
				require.ErrorIs(t, err, os.ErrNotExist)

				// dirfs answers Readlink and Lstat from its in-memory copy, so
				// check the disk separately.
				if onDisk != "" {
					got, err := os.Readlink(filepath.Join(onDisk, tt.wantPath))
					require.NoError(t, err)
					require.Equal(t, tt.target, got)
					_, err = os.Lstat(filepath.Join(onDisk, unprefixed))
					require.ErrorIs(t, err, os.ErrNotExist)
				}
			})
		}
	}
}

func TestSubFSLinkUnderRoot(t *testing.T) {
	tests := []struct {
		name     string
		oldname  string // link source, a path on the SubFS
		newname  string // link to create, a path on the SubFS
		wantPath string // where the link must land on the base FS
		wantErr  error  // set when the source must not resolve
	}{
		{"absolute names", "/a/orig", "/b/hard", "/sub/b/hard", nil},
		// Tar headers carry relative names.
		{"relative names", "a/orig", "b/hard-rel", "/sub/b/hard-rel", nil},
		// A source that exists only outside the root is not reachable.
		{"source only outside the root", "/a/only-outside", "/b/miss", "", os.ErrNotExist},
	}
	for baseName, newBase := range subFSBases {
		for _, tt := range tests {
			t.Run(baseName+"/"+tt.name, func(t *testing.T) {
				base, onDisk := newBase(t)
				require.NoError(t, base.MkdirAll("/sub/a", 0o755))
				require.NoError(t, base.MkdirAll("/sub/b", 0o755))
				require.NoError(t, base.MkdirAll("/a", 0o755))
				require.NoError(t, base.MkdirAll("/b", 0o755))
				require.NoError(t, base.WriteFile("/sub/a/orig", []byte("inside"), 0o644))
				// Same-named files outside the root must never be the link source.
				require.NoError(t, base.WriteFile("/a/orig", []byte("outside"), 0o644))
				require.NoError(t, base.WriteFile("/a/only-outside", []byte("x"), 0o644))
				sub := &SubFS{FS: base, Root: "/sub"}

				err := sub.Link(tt.oldname, tt.newname)
				if tt.wantErr != nil {
					require.ErrorIs(t, err, tt.wantErr)
					return
				}
				require.NoError(t, err)

				// The link lands under the root and reads the inside file.
				got, err := base.ReadFile(tt.wantPath)
				require.NoError(t, err)
				require.Equal(t, "inside", string(got))

				// Reading back through the SubFS agrees with the base view.
				got, err = sub.ReadFile(tt.newname)
				require.NoError(t, err)
				require.Equal(t, "inside", string(got))

				// Nothing was created at the un-prefixed path outside the root.
				unprefixed := strings.TrimPrefix(tt.wantPath, "/sub")
				_, err = base.Lstat(unprefixed)
				require.ErrorIs(t, err, os.ErrNotExist)

				// dirfs answers Lstat from its in-memory copy, so check the
				// disk separately.
				if onDisk != "" {
					got, err := os.ReadFile(filepath.Join(onDisk, tt.wantPath))
					require.NoError(t, err)
					require.Equal(t, "inside", string(got))
					_, err = os.Lstat(filepath.Join(onDisk, unprefixed))
					require.ErrorIs(t, err, os.ErrNotExist)
				}
			})
		}
	}
}

// subFSMethods is every SubFS method that takes a path, each wrapped so the
// confinement tests can call it with one argument. Symlink's first argument
// is a link target, not a path, so it is fixed here.
var subFSMethods = map[string]func(sub *SubFS, name string) error{
	"OpenReaderAt": func(s *SubFS, n string) error { _, err := s.OpenReaderAt(n); return err },
	"OpenFile":     func(s *SubFS, n string) error { _, err := s.OpenFile(n, os.O_RDONLY, 0); return err },
	"Create":       func(s *SubFS, n string) error { _, err := s.Create(n); return err },
	"ReadFile":     func(s *SubFS, n string) error { _, err := s.ReadFile(n); return err },
	"WriteFile":    func(s *SubFS, n string) error { return s.WriteFile(n, []byte("x"), 0o644) },
	"Mkdir":        func(s *SubFS, n string) error { return s.Mkdir(n, 0o755) },
	"MkdirAll":     func(s *SubFS, n string) error { return s.MkdirAll(n, 0o755) },
	"ReadDir":      func(s *SubFS, n string) error { _, err := s.ReadDir(n); return err },
	"Stat":         func(s *SubFS, n string) error { _, err := s.Stat(n); return err },
	"Lstat":        func(s *SubFS, n string) error { _, err := s.Lstat(n); return err },
	"Remove":       func(s *SubFS, n string) error { return s.Remove(n) },
	"Chmod":        func(s *SubFS, n string) error { return s.Chmod(n, 0o644) },
	"Chown":        func(s *SubFS, n string) error { return s.Chown(n, 0, 0) },
	"Lchown":       func(s *SubFS, n string) error { return s.Lchown(n, 0, 0) },
	"Chtimes":      func(s *SubFS, n string) error { return s.Chtimes(n, time.Time{}, time.Time{}) },
	"Symlink":      func(s *SubFS, n string) error { return s.Symlink("target", n) },
	"Link old":     func(s *SubFS, n string) error { return s.Link(n, "/inside/hl") },
	"Link new":     func(s *SubFS, n string) error { return s.Link("/inside/file", n) },
	"Readlink":     func(s *SubFS, n string) error { _, err := s.Readlink(n); return err },
	"Mknod":        func(s *SubFS, n string) error { return s.Mknod(n, 0o644, 0) },
	"Readnod":      func(s *SubFS, n string) error { _, err := s.Readnod(n); return err },
	"SetXattr":     func(s *SubFS, n string) error { return s.SetXattr(n, "user.k", []byte("v")) },
	"GetXattr":     func(s *SubFS, n string) error { _, err := s.GetXattr(n, "user.k"); return err },
	"RemoveXattr":  func(s *SubFS, n string) error { return s.RemoveXattr(n, "user.k") },
	"ListXattrs":   func(s *SubFS, n string) error { _, err := s.ListXattrs(n); return err },
}

// TestSubFSRejectsPathsAboveRoot checks that no method accepts a path that
// climbs above the root, on either base, and that nothing is created at the
// place such a path would have named.
func TestSubFSRejectsPathsAboveRoot(t *testing.T) {
	escapes := []string{"..", "../x", "/../x", "a/../../x", "./../x"}
	for baseName, newBase := range subFSBases {
		for method, call := range subFSMethods {
			for _, name := range escapes {
				t.Run(baseName+"/"+method+"/"+name, func(t *testing.T) {
					base, _ := newBase(t)
					require.NoError(t, base.MkdirAll("/sub/inside", 0o755))
					require.NoError(t, base.WriteFile("/sub/inside/file", []byte("in"), 0o644))
					sub := &SubFS{FS: base, Root: "/sub"}

					err := call(sub, name)
					require.ErrorIs(t, err, fs.ErrInvalid)

					// The sibling of the root the path named does not exist.
					_, err = base.Lstat("/x")
					require.ErrorIs(t, err, os.ErrNotExist)
				})
			}
		}
	}
}

// TestSubFSAcceptsPathsWithinRoot checks that the forms callers rely on still
// resolve under the root: absolute, relative, empty, dot, and a ".." that
// stays inside.
func TestSubFSAcceptsPathsWithinRoot(t *testing.T) {
	tests := []struct {
		name string
		want string // path on the base
	}{
		{"/a/f", "/sub/a/f"},
		{"a/f", "/sub/a/f"},
		{"./a/f", "/sub/a/f"},
		{"a/../b/f", "/sub/b/f"},
		{"/a/../b/f", "/sub/b/f"},
	}
	for baseName, newBase := range subFSBases {
		for _, tt := range tests {
			t.Run(baseName+"/"+tt.name, func(t *testing.T) {
				base, _ := newBase(t)
				require.NoError(t, base.MkdirAll("/sub/a", 0o755))
				require.NoError(t, base.MkdirAll("/sub/b", 0o755))
				sub := &SubFS{FS: base, Root: "/sub"}

				require.NoError(t, sub.WriteFile(tt.name, []byte("x"), 0o644))
				got, err := base.ReadFile(tt.want)
				require.NoError(t, err)
				require.Equal(t, "x", string(got))
			})
		}
		t.Run(baseName+"/root itself", func(t *testing.T) {
			base, _ := newBase(t)
			require.NoError(t, base.MkdirAll("/sub/a", 0o755))
			sub := &SubFS{FS: base, Root: "/sub"}
			for _, name := range []string{"", ".", "/"} {
				entries, err := sub.ReadDir(name)
				require.NoError(t, err, "ReadDir(%q)", name)
				require.Len(t, entries, 1, "ReadDir(%q)", name)
			}
		})
	}
}

// TestSubFSSymlinkResolutionIsLeftToBase pins the part of the contract SubFS
// does not provide: a symlink under the root is resolved by the base, which
// knows nothing about the root. A dirfs confines the result to its own base
// directory; a memfs does not confine it at all. If the base ever starts
// confining to the SubFS root, this test should be updated, not deleted.
func TestSubFSSymlinkResolutionIsLeftToBase(t *testing.T) {
	for baseName, newBase := range subFSBases {
		t.Run(baseName, func(t *testing.T) {
			base, _ := newBase(t)
			require.NoError(t, base.MkdirAll("/sub/home", 0o755))
			require.NoError(t, base.MkdirAll("/etc", 0o755))
			require.NoError(t, base.WriteFile("/etc/target", []byte("orig"), 0o644))
			sub := &SubFS{FS: base, Root: "/sub"}

			// The link itself lands under the root (PSEC-2285).
			require.NoError(t, sub.Symlink("/etc/target", "/home/abs"))
			got, err := base.Readlink("/sub/home/abs")
			require.NoError(t, err)
			require.Equal(t, "/etc/target", got)

			// Writing through it is decided by the base.
			err = sub.WriteFile("/home/abs", []byte("new"), 0o644)
			onBase, _ := base.ReadFile("/etc/target")
			switch baseName {
			case "dirfs":
				require.Error(t, err, "os.Root refuses a link that leaves the base directory")
				require.Equal(t, "orig", string(onBase))
			case "memfs":
				require.NoError(t, err)
				require.Equal(t, "new", string(onBase), "memfs resolves the absolute target against its own root")
			default:
				t.Fatalf("unknown base %q", baseName)
			}
		})
	}
}
