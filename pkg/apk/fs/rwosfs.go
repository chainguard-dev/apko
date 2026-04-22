// Copyright 2022, 2023 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fs

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/chainguard-dev/clog"
	"golang.org/x/sys/unix"
)

type dirFSOpts struct {
	caseSensitive    bool
	caseSensitiveSet bool
	mkdir            bool
}

// DirFSOption is an option for DirFS
type DirFSOption func(*dirFSOpts) error

// DirFSWithCaseSensitive allows you to specify whether the underlying filesystem
// should be treated as case-sensitive or insensitive. If you do not specify this,
// it determines it by testing the underlying filesystem.
// Normally you should let the filesystem determine this, but sometimes this can be useful.
func DirFSWithCaseSensitive(caseSensitive bool) DirFSOption {
	return func(opts *dirFSOpts) error {
		opts.caseSensitive = caseSensitive
		opts.caseSensitiveSet = true
		return nil
	}
}

// WithCreateDir allows you to specify whether the underlying directory
// should be created if it does not exist. Default is false.
func WithCreateDir() DirFSOption {
	return func(opts *dirFSOpts) error {
		opts.mkdir = true
		return nil
	}
}

func DirFS(ctx context.Context, dir string, opts ...DirFSOption) FullFS {
	log := clog.FromContext(ctx).With("dir", dir)

	var options dirFSOpts
	for _, opt := range opts {
		if err := opt(&options); err != nil {
			log.Warn("error applying option", "error", err)
			return nil
		}
	}

	m := NewMemFS()

	// check if the underlying filesystem is case-sensitive
	fi, err := os.Stat(dir)
	switch {
	case err != nil && !os.IsNotExist(err):
		log.Warn("error checking dir", "error", err)
		return nil
	case err != nil && os.IsNotExist(err):
		if !options.mkdir {
			log.Warn("dir does not exist")
			return nil
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			log.Warn("error creating dir", "error", err)
			return nil
		}
	case !fi.IsDir():
		log.Warn("not a directory")
		return nil
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		log.Warn("error opening root", "error", err)
		return nil
	}

	var caseSensitive bool
	if options.caseSensitiveSet {
		caseSensitive = options.caseSensitive
	} else {
		// Probe the underlying filesystem through the root so the probe is
		// subject to the same sandboxing as every other write. We cannot reuse
		// the caller's TempDir because it might be on a different filesystem.
		for i := 0; ; i++ {
			filename := fmt.Sprintf("test-dirfs-%d", i)
			if _, err := root.Stat(filename); err == nil {
				continue
			}
			if err := root.WriteFile(filename, []byte("test"), 0o600); err != nil {
				caseSensitive = false // If this fails, let's just assume it's not case sensitive.
				break
			}
			if _, err := root.Stat(strings.ToUpper(filename)); err != nil {
				caseSensitive = true
			}
			// clean up our own messes
			_ = root.Remove(filename)
			break
		}
	}

	var caseMap map[string]string
	if !caseSensitive {
		caseMap = map[string]string{}
	}
	f := &dirFS{
		base:      dir,
		root:      root,
		overrides: m,
		caseMap:   caseMap,
	}
	// Safety net for the library-consumer case where the dirFS is stashed
	// inside another type (e.g. apk.New's fallback) and never reachable for
	// explicit Close. Stopped by Close when it runs deterministically.
	f.cleanup = runtime.AddCleanup(f, func(r *os.Root) { _ = r.Close() }, root)
	// Seed overrides by walking the backing tree through the root. This
	// refuses to follow any pre-existing symlink whose target escapes base,
	// and root.Readlink gives us consistent sandbox semantics with the rest
	// of the dirFS API surface.
	_ = fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == "." {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		mode := fi.Mode()
		perm := mode.Perm()
		switch mode.Type() {
		case fs.ModeDir:
			fullPerm := os.ModeDir | perm
			err = f.overrides.Mkdir(path, fullPerm)
		case fs.ModeSymlink:
			var target string
			target, err = root.Readlink(path)
			if err == nil {
				err = f.overrides.Symlink(target, path)
			}
		case fs.ModeCharDevice:
			var dev int
			sys := fi.Sys()
			st1, ok1 := sys.(*syscall.Stat_t)
			st2, ok2 := sys.(*unix.Stat_t)
			switch {
			case ok1:
				dev = int(st1.Rdev)
			case ok2:
				dev = int(st2.Rdev)
			default:
				return fmt.Errorf("unsupported type %T", sys)
			}
			err = f.overrides.Mknod(path, uint32(unix.S_IFCHR|mode), dev)
		default:
			var memFile File
			memFile, err = f.overrides.OpenFile(path, os.O_CREATE, perm)
			if memFile != nil {
				_ = memFile.Close()
			}
		}
		return err
	})

	return f
}

// dirFS represents a FullFS implementation based on a directory on disk.
// For those features that are not supported, e.g. activities that are non-permissioned
// or unsupported by the underlying filesystem or operating system, it keeps a separate map
// in memory.
//
// How case-sensitivity works.
// If the underlying filesystem is case-sensitive, then all files are mapped both on disk and in memory,
// with content solely on disk to save space.
// If the underlying filesystem is case-insensitive, then we can only have one variant of each file on disk,
// but multiple in memory. Each file provided is converted to lower-case. That is then used as a key
// in a map, whose value is the one that is on disk. Any other variant is in memory.
// If the case-sensitive filename you are looking for is the same as the value in the map, it is on disk,
// else in memory.
type dirFS struct {
	base string
	// root is a capability-style handle scoped to base. All disk operations on
	// caller-supplied paths go through it so path resolution can never escape
	// base via symlinks, hard links, absolute path components, or "..".
	root *os.Root
	// cleanup releases the root FD on garbage collection as a safety net for
	// callers that can't reach Close() (notably the apk.New fallback which
	// stashes the FullFS inside *APK). Deterministic release via Close() is
	// still preferred.
	//
	// TODO: revisit and replace with `Close() error` on the FullFS interface
	// once we're willing to take the breaking change across in-tree
	// implementers and library consumers.
	cleanup runtime.Cleanup
	// overrides is a map of overrides for things that could not be kept on disk because of permission,
	// filesystem or operating system limitations.
	// It will include all directories, but no file contents.
	// If there are permissions in memory, they override the disk.
	overrides FullFS
	// caseMap if non-nil, underlying filesystem is case-insensitive, so only one variant of each file
	// can exist on disk. Maps the case-sensitive to the case-insensitive variant
	caseMap      map[string]string
	caseMapMutex sync.Mutex
}

// Close releases the underlying *os.Root file descriptor. A GC cleanup is also
// registered as a safety net for consumers who cannot reach this method.
// Calling Close more than once is safe.
func (f *dirFS) Close() error {
	if f.root == nil {
		return nil
	}
	f.cleanup.Stop()
	err := f.root.Close()
	f.root = nil
	return err
}

func (f *dirFS) Readlink(name string) (string, error) {
	// The underlying filesystem might not support symlinks, and it might be case-insensitive, so just
	// use the one in memory.
	target, err := f.overrides.Readlink(name)
	if err != nil {
		return "", err
	}
	return target, err
}

// Open open a file for reading. Returns fs.File.
// If the file has the wrong permissions for reading, it tries to
// change them, and then change them back when closing.
// This only works if the user reading the file actually has
// permissions to change the file permissions.
func (f *dirFS) Open(name string) (fs.File, error) {
	return f.open(name)
}

func (f *dirFS) open(name string) (*fileImpl, error) {
	rel := f.relPath(name)
	baseName := filepath.Base(name)
	if f.caseSensitiveOnDisk(name) {
		file, err := f.root.Open(rel)
		if err == nil {
			return &fileImpl{
				file: file,
				name: baseName,
				root: f.root,
				rel:  rel,
			}, nil
		}
		if !os.IsPermission(err) {
			return nil, err
		}
		// get the original permissions
		fi, err := f.root.Stat(rel)
		if err != nil {
			return nil, fmt.Errorf("unable to stat file %s: %w", name, err)
		}
		// Try to change permissions and open again.
		if err := f.root.Chmod(rel, 0o600); err != nil {
			return nil, fmt.Errorf("unable to read file or change permissions: %s", name)
		}
		file, err = f.root.Open(rel)
		if err != nil {
			return nil, fmt.Errorf("unable to read file even after change permissions: %s", name)
		}
		perms := fi.Mode()
		return &fileImpl{
			file:  file,
			name:  baseName,
			root:  f.root,
			rel:   rel,
			perms: &perms,
		}, nil
	}

	file, err := f.overrides.OpenReaderAt(name)
	if err != nil {
		return nil, err
	}
	return &fileImpl{file: file, name: baseName}, nil
}

// Open open a file for reading. Returns fs.File.
// If the file has the wrong permissions for reading, it tries to
// change them, and then change them back when closing.
// This only works if the user reading the file actually has
// permissions to change the file permissions.
func (f *dirFS) OpenFile(name string, flag int, perm fs.FileMode) (File, error) {
	var (
		file File
		err  error
	)
	if flag&os.O_CREATE == os.O_CREATE {
		file, err = f.overrides.OpenFile(name, flag, perm)
		if err != nil {
			return nil, err
		}
		// do we create it on disk?
		if f.createOnDisk(name) {
			_ = file.Close()
			file, err = f.root.OpenFile(f.relPath(name), flag, perm)
			if err != nil {
				return nil, err
			}
		}
	} else {
		if f.caseSensitiveOnDisk(name) {
			file, err = f.root.OpenFile(f.relPath(name), flag, perm)
		} else {
			file, err = f.overrides.OpenFile(name, flag, perm)
		}
		if err != nil {
			return nil, err
		}
	}
	return file, nil
}

func (f *dirFS) OpenReaderAt(name string) (File, error) {
	return f.open(name)
}

func (f *dirFS) Stat(name string) (fs.FileInfo, error) {
	var (
		fi  fs.FileInfo
		err error
	)
	mi, err := f.overrides.Stat(name)
	if err != nil {
		return nil, err
	}
	if f.caseSensitiveOnDisk(name) {
		fi, err = f.root.Stat(f.relPath(name))
		if err != nil {
			return nil, err
		}
	} else {
		fi = mi
	}
	return &fileInfo{
		file: fi,
		mem:  mi,
	}, nil
}
func (f *dirFS) Lstat(name string) (fs.FileInfo, error) {
	return f.overrides.Lstat(name)
}

func (f *dirFS) Create(name string) (File, error) {
	// if the underlying filesystem is case-insensitive, check if the file exists and, if so,
	// do it only in memory.
	var (
		file File
		err  error
	)
	file, err = f.overrides.Create(name)
	if err != nil {
		return nil, err
	}
	// do we create it on disk?
	if f.createOnDisk(name) {
		// close the memory one
		_ = file.Close()
		file, err = f.root.Create(f.relPath(name))
		if err != nil {
			return nil, err
		}
	}

	return file, err
}

func (f *dirFS) Remove(name string) error {
	if err := f.overrides.Remove(name); err != nil {
		return err
	}
	if f.removeOnDisk(name) {
		return f.root.Remove(f.relPath(name))
	}
	return nil
}

func (f *dirFS) ReadDir(name string) ([]fs.DirEntry, error) {
	// get those on disk
	var (
		onDisk, inMem []fs.DirEntry
		err           error
	)
	if f.caseSensitiveOnDisk(name) {
		// *os.Root does not expose ReadDir; open the directory through it and
		// read entries from the returned *os.File.
		dir, err := f.root.Open(f.relPath(name))
		if err != nil {
			return nil, err
		}
		onDisk, err = dir.ReadDir(-1)
		_ = dir.Close()
		if err != nil {
			return nil, err
		}
	}
	// get those in memory
	inMem, err = f.overrides.ReadDir(name)
	if err != nil {
		return nil, err
	}
	// possibilities:
	// - directory on disk is case-insensitive and not the unique one: no entries on disk
	// - directory on disk is case-insensitive and the unique one: disk entries and memory entries; all disk must be in mem, but mem may have more
	// - directory on disk is case-sensitive: disk entries and memory entries; all disk must be in mem, but mem may have more
	//
	// either way, memory always should be >= disk
	diskEntries := make(map[string]fs.DirEntry, len(onDisk))
	for _, d := range onDisk {
		diskEntries[d.Name()] = d
	}

	dirEntries := make([]fs.DirEntry, 0, len(inMem))
	for _, m := range inMem {
		f := m
		if d, ok := diskEntries[m.Name()]; ok {
			f = d
		}
		dirEntries = append(dirEntries, &dirEntry{disk: f, mem: m})
	}
	// we need them in a consistent order
	sort.Slice(dirEntries, func(i, j int) bool {
		return dirEntries[i].Name() < dirEntries[j].Name()
	})

	return dirEntries, nil
}
func (f *dirFS) ReadFile(name string) ([]byte, error) {
	if f.caseSensitiveOnDisk(name) {
		return f.root.ReadFile(f.relPath(name))
	}
	return f.overrides.ReadFile(name)
}
func (f *dirFS) WriteFile(name string, b []byte, mode fs.FileMode) error {
	if f.createOnDisk(name) {
		if err := f.root.WriteFile(f.relPath(name), b, mode); err != nil {
			return err
		}
	}

	// Always cache the actual content to ensure ReadFile returns correct data
	// Previously cached empty buffer for disk files, causing ReadFile to return zeros
	return f.overrides.WriteFile(name, b, mode)
}

func (f *dirFS) Readnod(name string) (dev int, err error) {
	if f.caseSensitiveOnDisk(name) {
		if _, err := f.root.Stat(f.relPath(name)); err != nil {
			return 0, err
		}
	}
	return f.overrides.Readnod(name)
}

func (f *dirFS) Link(oldname, newname string) error {
	if f.createOnDisk(newname) {
		// *os.Root enforces that both endpoints resolve within base, including
		// refusing to traverse any attacker-planted symlink in either path.
		if err := f.root.Link(f.relPath(oldname), f.relPath(newname)); err != nil {
			return err
		}
	}
	return f.overrides.Link(oldname, newname)
}

func (f *dirFS) Symlink(oldname, newname string) error {
	// The target (oldname) is stored verbatim, which preserves legitimate APK
	// semantics (e.g., absolute paths within the image). *os.Root refuses to
	// traverse the symlink at use time if it would escape the root.
	if f.createOnDisk(newname) {
		if err := f.root.Symlink(oldname, f.relPath(newname)); err != nil {
			return err
		}
	}
	return f.overrides.Symlink(oldname, newname)
}

func (f *dirFS) MkdirAll(name string, perm fs.FileMode) error {
	// just in case, because some underlying systems miss this
	fullPerm := os.ModeDir | perm
	if f.createOnDisk(name) {
		// *os.Root rejects type bits in the mode; strip to permission bits.
		if err := f.root.MkdirAll(f.relPath(name), fullPerm.Perm()); err != nil {
			return err
		}
	}
	return f.overrides.MkdirAll(name, fullPerm)
}

func (f *dirFS) Mkdir(name string, perm fs.FileMode) error {
	// just in case, because some underlying systems miss this
	fullPerm := os.ModeDir | perm
	if f.createOnDisk(name) {
		// *os.Root rejects type bits in the mode; strip to permission bits.
		if err := f.root.Mkdir(f.relPath(name), fullPerm.Perm()); err != nil {
			return err
		}
	}
	return f.overrides.Mkdir(name, fullPerm)
}

// isUnsupportedByFS reports whether an error from a best-effort on-disk
// metadata call is one we expect to ignore:
//   - ENOTSUP/EOPNOTSUPP/ENOSYS: the filesystem or platform can't perform the
//     operation (e.g. a FUSE mount that ignores mode bits).
//   - EPERM: the process lacks privilege (e.g. chown as non-root without
//     CAP_CHOWN, chmod of a not-owned or immutable file). This is the
//     dominant failure mode for unprivileged builds.
//
// In-memory overrides remain the authoritative source for mode/ownership, so
// the build still produces a correctly-attributed tar. Real errors (path
// escapes, I/O failures, missing files) still surface.
func isUnsupportedByFS(err error) bool {
	return errors.Is(err, syscall.ENOTSUP) ||
		errors.Is(err, syscall.EOPNOTSUPP) ||
		errors.Is(err, syscall.ENOSYS) ||
		errors.Is(err, syscall.EPERM)
}

func (f *dirFS) Chmod(path string, perm fs.FileMode) error {
	if f.caseSensitiveOnDisk(path) {
		if err := f.root.Chmod(f.relPath(path), perm); err != nil && !isUnsupportedByFS(err) {
			return err
		}
	}
	return f.overrides.Chmod(path, perm)
}

func (f *dirFS) Chown(path string, uid, gid int) error {
	if f.caseSensitiveOnDisk(path) {
		if err := f.root.Chown(f.relPath(path), uid, gid); err != nil && !isUnsupportedByFS(err) {
			return err
		}
	}
	return f.overrides.Chown(path, uid, gid)
}

func (f *dirFS) Chtimes(path string, atime time.Time, mtime time.Time) error {
	if err := f.root.Chtimes(f.relPath(path), atime, mtime); err != nil {
		return fmt.Errorf("unable to change times: %w", err)
	}
	return f.overrides.Chtimes(path, atime, mtime)
}

// Mknod stores device metadata in the memFS overrides (the authoritative
// layer) and best-effort materializes the node on disk so other operations
// that consult disk first still find an entry.
//
// os.Root has no Mknod of its own; the disk side is platform-specific and
// implemented in rwosfs_mknod_{linux,other}.go via mknodOnDisk.
func (f *dirFS) Mknod(name string, mode uint32, dev int) error {
	if f.caseSensitiveOnDisk(name) {
		if err := f.mknodOnDisk(f.relPath(name), mode, dev); err != nil {
			return err
		}
	}
	return f.overrides.Mknod(name, mode, dev)
}

// placeholderOnDisk creates an empty file through the root so that later
// Stat/Open calls that consult disk first find something. Device metadata is
// tracked in the in-memory overrides; this entry is a visibility stub only.
func (f *dirFS) placeholderOnDisk(rel string) error {
	if err := f.root.WriteFile(rel, nil, 0); err != nil {
		return fmt.Errorf("unable to create placeholder on disk: %w", err)
	}
	return nil
}

func (f *dirFS) SetXattr(path string, attr string, data []byte) error {
	// the underlying filesystem might or might not support xattrs
	// but we have info on every file in memory, so might as well store it there.
	return f.overrides.SetXattr(path, attr, data)
}
func (f *dirFS) GetXattr(path string, attr string) ([]byte, error) {
	return f.overrides.GetXattr(path, attr)
}
func (f *dirFS) RemoveXattr(path string, attr string) error {
	return f.overrides.RemoveXattr(path, attr)
}
func (f *dirFS) ListXattrs(path string) (map[string][]byte, error) {
	return f.overrides.ListXattrs(path)
}
func (f *dirFS) Sub(path string) (FullFS, error) {
	return f.overrides.Sub(path)
}

const pathSeparator = string(os.PathSeparator)

// relPath normalizes a caller-supplied path into a clean, root-relative form
// suitable for use with *os.Root operations.
//
// It handles two things that *os.Root does not handle gracefully on its own:
//   - empty / "/" / absolute-looking inputs, which *os.Root rejects as "path
//     escapes from parent" — here we strip to a root-relative form.
//   - intermediate ".." components, which *os.Root walks against the real
//     filesystem (so "a/c/../b" fails if "c" doesn't exist). filepath.Clean
//     collapses them lexically before we hand the path to the root.
//
// Null-byte paths and ".." components that escape the root are left to
// *os.Root to reject; both yield clear errors from the stdlib.
func (f *dirFS) relPath(p string) string {
	clean := strings.TrimSuffix(strings.TrimPrefix(p, pathSeparator), pathSeparator)
	if clean == "" {
		return "."
	}
	return filepath.Clean(clean)
}

func (f *dirFS) caseSensitiveOnDisk(p string) bool {
	if f.caseMap == nil {
		return true
	}
	f.caseMapMutex.Lock()
	defer f.caseMapMutex.Unlock()
	p = standardizePath(p)
	key := strings.ToLower(p)
	result, ok := f.caseMap[key]
	if !ok {
		return true
	}
	return result == p
}

// createOnDisk given a path p, determine if it should be created on disk, and, if relevant,
// add it to the caseMap. If the file already exists on disk, also returns true.
// This func is responsible solely for determining if you _should_ created it on disk.
// If that would cause a conflict, that is up to the calling routing to figure out.
func (f *dirFS) createOnDisk(p string) bool {
	if f.caseMap == nil {
		return true
	}
	f.caseMapMutex.Lock()
	defer f.caseMapMutex.Unlock()
	p = standardizePath(p)
	key := strings.ToLower(p)
	result, ok := f.caseMap[key]
	if !ok {
		f.caseMap[key] = p
		return true
	}
	return result == p
}

// removeOnDisk given a path p, determine if it should be removed from disk, and, if relevant,
// remove it from the caseMap.
func (f *dirFS) removeOnDisk(p string) (removeOnDisk bool) {
	f.caseMapMutex.Lock()
	defer f.caseMapMutex.Unlock()
	key := strings.ToLower(p)
	if f.caseMap == nil {
		removeOnDisk = true
	} else if v, ok := f.caseMap[key]; ok && v == p {
		delete(f.caseMap, key)
		removeOnDisk = true
	}
	return
}

type file File
type fileImpl struct {
	file
	name string
	// root and rel are populated when the underlying file lives on disk so
	// permission restoration in Close() goes through the sandboxed root.
	root  *os.Root
	rel   string
	perms *os.FileMode
}

func (f fileImpl) Close() error {
	if err := f.file.Close(); err != nil {
		return err
	}
	if f.perms != nil && f.root != nil {
		return f.root.Chmod(f.rel, *f.perms)
	}
	return nil
}

type fileInfo struct {
	file fs.FileInfo
	mem  fs.FileInfo
}

func (f *fileInfo) Name() string {
	return f.file.Name()
}
func (f *fileInfo) Size() int64 {
	return f.file.Size()
}
func (f *fileInfo) Mode() fs.FileMode {
	return f.mem.Mode()
}
func (f *fileInfo) ModTime() time.Time {
	return f.file.ModTime()
}
func (f *fileInfo) IsDir() bool {
	return f.file.IsDir()
}
func (f *fileInfo) Sys() any {
	return f.mem.Sys()
}

type dirEntry struct {
	disk fs.DirEntry
	mem  fs.DirEntry
}

func (d *dirEntry) Name() string {
	return d.disk.Name()
}

func (d *dirEntry) IsDir() bool {
	return d.disk.IsDir()
}

func (d *dirEntry) Type() fs.FileMode {
	return d.mem.Type()
}

func (d *dirEntry) Info() (fs.FileInfo, error) {
	diskInfo, err := d.disk.Info()
	if err != nil {
		return nil, err
	}
	memInfo, err := d.mem.Info()
	if err != nil {
		return nil, err
	}
	return &fileInfo{file: diskInfo, mem: memInfo}, nil
}

func standardizePath(p string) string {
	if p[0] == '/' {
		p = p[1:]
	}
	return p
}
