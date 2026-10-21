// Copyright 2023 Chainguard, Inc.
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

package tarfs

import (
	"archive/tar"
	"bytes"
	"crypto/sha1" //nolint:gosec // APK file checksums use SHA-1.
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"chainguard.dev/apko/pkg/apk/apk"
	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/cas"
)

const (
	pathSep = "/"
	// maxLinks maximum permitted depths of symlinks, to prevent infinite recursion
	// matches what Linux kernel does from 4.2 onwards, see https://man7.org/linux/man-pages/man7/path_resolution.7.html
	maxLinks = 40

	xattrTarPAXRecordsPrefix = "SCHILY.xattr."
)

var _ apk.WriteHeaderer = (*memFS)(nil)

// memFS references package contents by digest when the source supports it.
// Other sources are read by name, and writable opens buffer the contents.
type memFS struct {
	tree *node

	blobs *cas.Union
}

func New() *memFS {
	return &memFS{
		tree: &node{
			dir:       true,
			children:  map[string]*node{},
			xattrs:    map[string][]byte{},
			hardlinks: map[string]*tar.Header{},
			name:      "/",
			mode:      fs.ModeDir | 0o755,
		},
		blobs: cas.NewUnion(),
	}
}

func checksumFromHeader(header *tar.Header) ([]byte, error) {
	hexsum, ok := header.PAXRecords["APK-TOOLS.checksum.SHA1"]
	if !ok {
		return nil, nil
	}
	if b64, ok := strings.CutPrefix(hexsum, "Q1"); ok {
		checksum, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("decoding base64 checksum from header for %q: %w", header.Name, err)
		}
		return checksum, nil
	}
	checksum, err := hex.DecodeString(hexsum)
	if err != nil {
		return nil, fmt.Errorf("decoding hex checksum from header for %q: %w", header.Name, err)
	}
	return checksum, nil
}

func (m *memFS) WriteHeader(hdr tar.Header, src fs.FS, pkg *apk.Package) (bool, error) {
	if hdr.Typeflag != tar.TypeReg {
		return m.WriteEntry(apk.Entry{Header: hdr}, nil, pkg)
	}
	if blobs, ok := src.(interface {
		cas.Store
		Digest(string) (cas.Digest, error)
	}); ok {
		digest, err := blobs.Digest(hdr.Name)
		if err == nil {
			return m.WriteEntry(apk.Entry{Header: hdr, Digest: digest}, blobs, pkg)
		}
		if !errors.Is(err, errors.ErrUnsupported) {
			return false, err
		}
	}
	checksum, err := checksumFromHeader(&hdr)
	if err != nil {
		return false, err
	}
	if checksum == nil {
		return false, fmt.Errorf("checksum is nil for %s", hdr.Name)
	}
	if src == nil {
		return false, fmt.Errorf("missing source filesystem for %q", hdr.Name)
	}
	want := newEntryNode(filepath.Base(hdr.Name), &hdr, cas.Digest{}, pkg)
	want.source = &fileSource{fs: src, name: hdr.Name}
	want.checksum = checksum
	return m.installHeader(hdr, want, nil)
}

// WriteEntry installs a package entry without copying its contents from blobs.
func (m *memFS) WriteEntry(e apk.Entry, blobs cas.Store, pkg *apk.Package) (bool, error) {
	hdr := e.Header
	if hdr.Typeflag == tar.TypeReg {
		if e.Digest == (cas.Digest{}) {
			return false, fmt.Errorf("missing content digest for %q", hdr.Name)
		}
		if blobs == nil {
			return false, fmt.Errorf("missing blob store for %q", hdr.Name)
		}
	}
	want := newEntryNode(filepath.Base(hdr.Name), &hdr, e.Digest, pkg)
	if hdr.Typeflag == tar.TypeReg {
		checksum, err := checksumFromHeader(&hdr)
		if err != nil {
			return false, err
		}
		want.checksum = checksum
	}
	return m.installHeader(hdr, want, blobs)
}

func (m *memFS) installHeader(hdr tar.Header, want *node, blobs cas.Store) (bool, error) {
	switch hdr.Typeflag {
	case tar.TypeDir:
		// special case, if the target already exists, and it is a symlink to a directory, we can accept it as is
		// otherwise, we need to create the directory.
		if fi, err := m.Stat(hdr.Name); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			if target, err := m.Readlink(hdr.Name); err == nil {
				if fi, err = m.Stat(target); err == nil && fi.IsDir() {
					return false, nil
				}
			}
		}
		if err := m.MkdirAll(hdr.Name, hdr.FileInfo().Mode().Perm()); err != nil {
			return false, fmt.Errorf("error creating directory %s: %w", hdr.Name, err)
		}
		if err := m.Chtimes(hdr.Name, hdr.AccessTime, hdr.ModTime); err != nil {
			return false, fmt.Errorf("error chtime on directory %s: %w", hdr.Name, err)
		}

		if err := m.setXattrsFromHeader(&hdr); err != nil {
			return false, err
		}

	case tar.TypeReg, tar.TypeSymlink:
		if hdr.Typeflag == tar.TypeSymlink {
			if target, err := m.Readlink(hdr.Name); err == nil && target == hdr.Linkname {
				return false, nil
			}
		}

		installed, err := m.writeEntry(hdr.Name, want, blobs)
		if err != nil {
			return false, fmt.Errorf("writing entry for %q: %w", hdr.Name, err)
		}
		if err := m.setXattrsFromHeader(&hdr); err != nil {
			return false, err
		}

		return installed, nil
	case tar.TypeLink:
		if err := m.link(hdr.Linkname, hdr.Name, &hdr); err != nil {
			return false, err
		}
	default:
		return false, fmt.Errorf("unsupported file type %s %v", hdr.Name, hdr.Typeflag)
	}

	return true, nil
}

func (m *memFS) setXattrsFromHeader(hdr *tar.Header) error {
	for k, v := range hdr.PAXRecords {
		attrName, ok := strings.CutPrefix(k, xattrTarPAXRecordsPrefix)
		if !ok {
			continue
		}
		if err := m.SetXattr(hdr.Name, attrName, []byte(v)); err != nil {
			return fmt.Errorf("error setting xattr %s on %s: %w", attrName, hdr.Name, err)
		}
	}
	return nil
}

// getNode returns the node for the given path. If the path is not found, it
// returns an error.
func (m *memFS) getNode(path string) (*node, error) {
	return m.getNodeCountLinks(path, 0)
}

func (m *memFS) getNodeCountLinks(path string, linkDepth int) (*node, error) {
	if path == "/" || path == "." {
		return m.tree, nil
	}
	parts := strings.Split(path, pathSep)
	node := m.tree
	traversed := make([]string, 0)
	for _, part := range parts {
		if part == "" {
			continue
		}
		if node.children == nil {
			return nil, fs.ErrNotExist
		}
		var ok bool
		node.mu.Lock()
		childNode, ok := node.children[part]
		// immediately unlock, no need to wait for defer. This is *really* important in the
		// case of symlinks below
		node.mu.Unlock()
		if !ok {
			return nil, fs.ErrNotExist
		}
		// what if it is a symlink?
		if childNode.mode&os.ModeSymlink != 0 {
			newDepth := linkDepth + 1
			if newDepth > maxLinks {
				return nil, fmt.Errorf("maximum symlink depth exceeded")
			}
			// getNode requires working on the absolute path, so we just resolve the path to an absolute path,
			// rather than struggling to clean up the path.
			// But, we have to make sure that we set it relative to where we are currently, rather than the parent of the path.
			// For example, /usr/lib64/foo/bar when /usr/lib64 -> lib, we want to resolve to /usr/lib rather than /usr/lib64/foo/lib
			linkTarget := childNode.linkTarget
			if !filepath.IsAbs(linkTarget) {
				linkTarget = filepath.Join(strings.Join(traversed, pathSep), linkTarget)
			}
			// now we have the absolute path, we can get the node
			// but that absolute path can cause us to try and hit something that is already locked
			// and since we are recursing, it will not get freed until we return
			// leading to a deadlock race condition
			targetNode, err := m.getNodeCountLinks(linkTarget, newDepth)
			if err != nil {
				return nil, err
			}
			childNode = targetNode
		}
		node = childNode
		traversed = append(traversed, part)
	}
	return node, nil
}

func (m *memFS) Mkdir(path string, perms fs.FileMode) error {
	// first see if the parent exists
	parent := filepath.Dir(path)
	anode, err := m.getNode(parent)
	if err != nil {
		return err
	}
	if anode.mode&fs.ModeDir == 0 {
		return fmt.Errorf("parent is not a directory")
	}
	// see if it exists
	anode.mu.Lock()
	defer anode.mu.Unlock()
	if _, ok := anode.children[filepath.Base(path)]; ok {
		return fs.ErrExist
	}
	// now create the directory
	anode.children[filepath.Base(path)] = &node{
		name:      filepath.Base(path),
		mode:      fs.ModeDir | perms,
		dir:       true,
		children:  map[string]*node{},
		xattrs:    map[string][]byte{},
		hardlinks: map[string]*tar.Header{},
	}
	return nil
}

func (m *memFS) Stat(path string) (fs.FileInfo, error) {
	node, err := m.getNode(path)
	if err != nil {
		return nil, err
	}
	if node.mode&fs.ModeSymlink != 0 {
		targetNode, err := m.getNode(node.linkTarget)
		if err != nil {
			return nil, err
		}
		node = targetNode
	}
	return node.fileInfo("", path), nil
}

func (m *memFS) Lstat(path string) (fs.FileInfo, error) {
	node, err := m.getNode(path)
	if err != nil {
		return nil, err
	}
	return node.fileInfo("", path), nil
}

func (m *memFS) MkdirAll(path string, perm fs.FileMode) error {
	parts := strings.Split(path, pathSep)
	traversed := make([]string, 0)
	anode := m.tree
	for _, part := range parts {
		if part == "" {
			continue
		}
		if anode.children == nil {
			anode.children = map[string]*node{}
		}
		var ok bool
		anode.mu.Lock()
		newnode, ok := anode.children[part]
		if !ok {
			newnode = &node{
				name:      part,
				mode:      fs.ModeDir | perm,
				dir:       true,
				children:  map[string]*node{},
				xattrs:    map[string][]byte{},
				hardlinks: map[string]*tar.Header{},
			}
			anode.children[part] = newnode
		}
		anode.mu.Unlock()
		// what if it is a symlink?
		if newnode.mode&os.ModeSymlink != 0 {
			linkTarget := newnode.linkTarget
			if !filepath.IsAbs(linkTarget) {
				linkTarget = filepath.Join(strings.Join(traversed, pathSep), linkTarget)
			}

			targetNode, err := m.getNode(linkTarget)
			if err != nil {
				return err
			}
			newnode = targetNode
		}
		if !newnode.dir {
			return fmt.Errorf("path is not a directory")
		}
		anode = newnode
		traversed = append(traversed, part)
	}
	return nil
}

func (m *memFS) Open(name string) (fs.File, error) {
	return m.OpenFile(name, os.O_RDONLY, 0o644)
}

func (m *memFS) OpenFile(name string, flag int, perm fs.FileMode) (apkfs.File, error) {
	return m.openFile(name, flag, perm, 0)
}

func (m *memFS) openFile(name string, flag int, perm fs.FileMode, linkCount int) (*memFile, error) {
	parent := filepath.Dir(name)
	base := filepath.Base(name)
	parentAnode, err := m.getNode(parent)
	if err != nil {
		return nil, err
	}
	if !parentAnode.dir {
		return nil, fmt.Errorf("parent is not a directory")
	}
	if parentAnode.children == nil {
		parentAnode.children = map[string]*node{}
	}
	parentAnode.mu.Lock()
	anode, ok := parentAnode.children[base]
	if !ok && flag&os.O_CREATE == 0 {
		parentAnode.mu.Unlock()

		if parent == name {
			return newMemFile(parentAnode, name, m, flag)
		}
		return nil, fs.ErrNotExist
	}
	if anode != nil && anode.dir {
		parentAnode.mu.Unlock()
		return nil, fmt.Errorf("is a directory")
	}
	if flag&os.O_CREATE != 0 {
		if !ok {
			// create the file
			anode = &node{
				name:      base,
				mode:      perm,
				dir:       false,
				digest:    cas.Empty,
				xattrs:    map[string][]byte{},
				hardlinks: map[string]*tar.Header{},
			}
			parentAnode.children[base] = anode
		}
	}
	parentAnode.mu.Unlock()
	// what if it is a symlink? Follow the symlink
	if anode.mode&os.ModeSymlink != 0 {
		localCount := linkCount + 1
		if localCount > maxLinks {
			return nil, fmt.Errorf("too many links")
		}
		linkTarget := anode.linkTarget
		if !filepath.IsAbs(linkTarget) {
			linkTarget = filepath.Join(parent, linkTarget)
		}
		return m.openFile(linkTarget, flag, perm, localCount)
	}

	return newMemFile(anode, name, m, flag)
}

func newEntryNode(name string, hdr *tar.Header, digest cas.Digest, pkg *apk.Package) *node {
	return &node{
		name:       name,
		mode:       hdr.FileInfo().Mode(),
		modTime:    hdr.ModTime,
		linkTarget: hdr.Linkname,
		digest:     digest,
		size:       hdr.Size,
		pkg:        pkg,
		xattrs:     map[string][]byte{},
		hardlinks:  map[string]*tar.Header{},
	}
}

// sameContents compares file digests or symlink targets, ignoring metadata.
func (m *memFS) sameContents(got, want *node) (bool, error) {
	switch {
	case got.mode.IsRegular() && want.mode.IsRegular():
		if got.source != nil || want.source != nil {
			checksum := got.checksum
			if got.buf != nil {
				sum := sha1.Sum(got.buf) //nolint:gosec // Compare with the legacy APK checksum.
				checksum = sum[:]
			}
			if checksum != nil && want.checksum != nil {
				return bytes.Equal(checksum, want.checksum), nil
			}
		}
		gotDigest, err := m.contentDigest(got)
		if err != nil {
			return false, err
		}
		wantDigest, err := m.contentDigest(want)
		if err != nil {
			return false, err
		}
		return gotDigest == wantDigest, nil
	case got.mode&os.ModeSymlink != 0 && want.mode&os.ModeSymlink != 0:
		return got.linkTarget == want.linkTarget, nil
	}
	return false, nil
}

func (m *memFS) contentDigest(n *node) (cas.Digest, error) {
	if n.buf != nil {
		return cas.Of(n.buf), nil
	}
	if n.source == nil {
		return n.digest, nil
	}
	r, err := m.openContents(n)
	if err != nil {
		return cas.Digest{}, err
	}
	defer r.Close()
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return cas.Digest{}, err
	}
	var digest cas.Digest
	h.Sum(digest[:0])
	return digest, nil
}

func (m *memFS) writeEntry(name string, want *node, blobs cas.Store) (bool, error) {
	parent := filepath.Dir(name)
	base := filepath.Base(name)

	parentAnode, err := m.getNode(parent)
	if err != nil {
		return false, err
	}

	if !parentAnode.dir {
		return false, fmt.Errorf("parent is not a directory")
	}
	if parentAnode.children == nil {
		parentAnode.children = map[string]*node{}
	}
	parentAnode.mu.Lock()
	defer parentAnode.mu.Unlock()

	got, ok := parentAnode.children[base]
	if !ok {
		if want.mode.IsRegular() && blobs != nil {
			m.blobs.Add(want.digest, blobs)
		}
		parentAnode.children[base] = want
		return true, nil
	}

	// Identical contents are fine whoever wrote them, e.g. go-apk's InitKeyring
	// writing a key that alpine-keys also ships.
	same, err := m.sameContents(got, want)
	if err != nil {
		return false, fmt.Errorf("comparing contents for %q: %w", name, err)
	}
	if same {
		return false, nil
	}

	if got.pkg == nil {
		return false, fmt.Errorf("conflicting file for %q, existing was not installed by a package", name)
	}
	pkg := want.pkg

	// If the existing file's package replaces the package we want to install, we don't need to write this file.
	if slices.Contains(got.pkg.Replaces, pkg.Name) {
		return false, nil
	}

	// Otherwise, determine if the package we are installing replaces the existing package.
	replaces := slices.Contains(pkg.Replaces, got.pkg.Name)

	// Or if they're from the same origin.
	sameOrigin := got.pkg.Origin == pkg.Origin

	// At this point we know the files conflict, but it's okay if this file replaces that one.
	if !sameOrigin && !replaces {
		return false, apk.FileConflictError{
			Path: name,
			Origins: map[string]string{
				got.pkg.Name: got.pkg.Origin,
				pkg.Name:     pkg.Origin,
			},
		}
	}

	// If we got here, they're different, but want replaces got, so it's all cool.
	if want.mode.IsRegular() && blobs != nil {
		m.blobs.Add(want.digest, blobs)
	}
	parentAnode.children[base] = want
	return true, nil
}

func (m *memFS) ReadFile(name string) ([]byte, error) {
	f, err := m.OpenFile(name, os.O_RDONLY, 0o644)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b := bytes.NewBuffer(nil)
	if _, err := io.Copy(b, f); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (m *memFS) WriteFile(name string, b []byte, mode fs.FileMode) error {
	f, err := m.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(f, bytes.NewBuffer(b)); err != nil {
		return err
	}
	return nil
}

func (m *memFS) ReadDir(parent string) ([]fs.DirEntry, error) {
	anode, err := m.getNode(parent)
	if err != nil {
		return nil, err
	}
	if !anode.dir {
		return nil, fmt.Errorf("not a directory")
	}
	var de = make([]fs.DirEntry, 0, len(anode.children))
	for name, node := range anode.children {
		de = append(de, fs.FileInfoToDirEntry(node.fileInfo(parent, name)))
	}
	// we need them in a consistent order, so sort them by filename, which is what os.ReadDir() does
	sort.Slice(de, func(i, j int) bool {
		return de[i].Name() < de[j].Name()
	})
	return de, nil
}

func (m *memFS) OpenReaderAt(name string) (apkfs.File, error) {
	return m.OpenFile(name, os.O_RDONLY, 0o644)
}

func (m *memFS) Mknod(path string, mode uint32, dev int) error {
	parent := filepath.Dir(path)
	base := filepath.Base(path)
	anode, err := m.getNode(parent)
	if err != nil {
		return err
	}
	anode.mu.Lock()
	defer anode.mu.Unlock()
	if _, ok := anode.children[base]; ok {
		return fs.ErrExist
	}
	anode.children[base] = &node{
		name:      base,
		mode:      fs.FileMode(mode) | os.ModeCharDevice | os.ModeDevice,
		major:     unix.Major(uint64(dev)),
		minor:     unix.Minor(uint64(dev)),
		xattrs:    map[string][]byte{},
		hardlinks: map[string]*tar.Header{},
		modTime:   anode.modTime,
	}

	return nil
}

func (m *memFS) Readnod(path string) (dev int, err error) {
	parent := filepath.Dir(path)
	base := filepath.Base(path)
	parentNode, err := m.getNode(parent)
	if err != nil {
		return 0, err
	}
	parentNode.mu.Lock()
	defer parentNode.mu.Unlock()
	anode, ok := parentNode.children[base]
	if !ok {
		return 0, fs.ErrNotExist
	}
	if anode.mode&os.ModeDevice != os.ModeDevice || anode.mode&os.ModeCharDevice != os.ModeCharDevice {
		return 0, fmt.Errorf("not a device")
	}
	return int(unix.Mkdev(anode.major, anode.minor)), nil
}

func (m *memFS) Chmod(path string, perm fs.FileMode) error {
	anode, err := m.getNode(path)
	if err != nil {
		return err
	}
	// need to change the mode, but keep the type
	anode.mode = perm | (anode.mode & os.ModeType)
	return nil
}

func (m *memFS) Chown(path string, uid, gid int) error {
	anode, err := m.getNode(path)
	if err != nil {
		return err
	}
	anode.uid = uid
	anode.gid = gid
	return nil
}

func (m *memFS) Chtimes(path string, atime time.Time, mtime time.Time) error {
	anode, err := m.getNode(path)
	if err != nil {
		return err
	}
	anode.modTime = mtime
	return nil
}

func (m *memFS) Create(name string) (apkfs.File, error) {
	// we are not honoring umask here, so choose a safer default than
	// 0o666 used by os.Create()
	return m.OpenFile(name, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o644)
}

func (m *memFS) Symlink(oldname, newname string) error {
	parent := filepath.Dir(newname)
	base := filepath.Base(newname)
	anode, err := m.getNode(parent)
	if err != nil {
		return err
	}
	anode.mu.Lock()
	defer anode.mu.Unlock()
	if _, ok := anode.children[base]; ok {
		return fs.ErrExist
	}
	anode.children[base] = &node{
		name:       base,
		mode:       0o777 | os.ModeSymlink,
		linkTarget: oldname,
		xattrs:     map[string][]byte{},
		hardlinks:  map[string]*tar.Header{},
		modTime:    anode.modTime,
	}
	return nil
}

func (m *memFS) link(oldname, newname string, hdr *tar.Header) error {
	parent := filepath.Dir(newname)
	base := filepath.Base(newname)
	anode, err := m.getNode(parent)
	if err != nil {
		return err
	}
	target, err := m.getNode(oldname)
	if err != nil {
		return fs.ErrNotExist
	}
	anode.mu.Lock()
	defer anode.mu.Unlock()
	if _, ok := anode.children[base]; ok {
		return fs.ErrExist
	}
	anode.children[base] = target
	target.linkCount++
	if hdr != nil {
		target.hardlinks[newname] = hdr
	}
	return nil
}

func (m *memFS) Link(oldname, newname string) error {
	return m.link(oldname, newname, nil)
}

func (m *memFS) Readlink(name string) (target string, err error) {
	parent := filepath.Dir(name)
	base := filepath.Base(name)
	parentNode, err := m.getNode(parent)
	if err != nil {
		return "", err
	}
	parentNode.mu.Lock()
	defer parentNode.mu.Unlock()
	anode, ok := parentNode.children[base]
	if !ok {
		return "", fs.ErrNotExist
	}
	if anode.mode&os.ModeSymlink == 0 {
		return "", fmt.Errorf("file is not a link")
	}
	return anode.linkTarget, nil
}

func (m *memFS) Remove(name string) error {
	parent := filepath.Dir(name)
	base := filepath.Base(name)
	anode, err := m.getNode(parent)
	if err != nil {
		return err
	}
	anode.mu.Lock()
	defer anode.mu.Unlock()
	if _, ok := anode.children[base]; !ok {
		return fs.ErrNotExist
	}
	if anode.children[base].linkCount > 0 {
		anode.children[base].linkCount--
	}
	delete(anode.children, base)
	return nil
}

func (m *memFS) SetXattr(path string, attr string, data []byte) error {
	node, err := m.getNode(path)
	if err != nil {
		return os.ErrNotExist
	}
	node.mu.Lock()
	defer node.mu.Unlock()
	node.xattrs[attr] = data
	return nil
}

func (m *memFS) GetXattr(path string, attr string) ([]byte, error) {
	node, err := m.getNode(path)
	if err != nil {
		return nil, os.ErrNotExist
	}
	node.mu.Lock()
	defer node.mu.Unlock()
	data, ok := node.xattrs[attr]
	if !ok {
		return nil, os.ErrNotExist
	}
	return data, nil
}

func (m *memFS) RemoveXattr(path string, attr string) error {
	node, err := m.getNode(path)
	if err != nil {
		return os.ErrNotExist
	}
	node.mu.Lock()
	defer node.mu.Unlock()
	// RemoveXattr is meant to ensure it does not exist; if it does not exist already, that is fine
	if _, ok := node.xattrs[attr]; !ok {
		return nil
	}
	delete(node.xattrs, attr)
	return nil
}

func (m *memFS) ListXattrs(path string) (map[string][]byte, error) {
	node, err := m.getNode(path)
	if err != nil {
		return nil, os.ErrNotExist
	}
	node.mu.Lock()
	defer node.mu.Unlock()
	// do not return the original, as someone might change it by accident.
	// Return a copy
	ret := make(map[string][]byte)
	for k, v := range node.xattrs {
		dst := make([]byte, len(v))
		copy(dst, v)
		ret[k] = dst
	}
	return ret, nil
}

func (m *memFS) Sub(path string) (apkfs.FullFS, error) {
	cleanPath := filepath.Clean(path)

	if cleanPath == "." {
		return m, nil
	}

	info, err := m.Stat(cleanPath)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("not a directory")
	}

	return &apkfs.SubFS{
		FS:   m,
		Root: cleanPath,
	}, nil
}

// memFile reads package contents until the node has a write buffer shared by all handles.
type memFile struct {
	node     *node
	fs       *memFS
	name     string
	openMode int

	r io.ReadCloser

	offset int64
}

func writable(openMode int) bool {
	return openMode&(os.O_WRONLY|os.O_RDWR|os.O_APPEND) != 0
}

func newMemFile(node *node, name string, memfs *memFS, openMode int) (*memFile, error) {
	m := &memFile{
		node:     node,
		fs:       memfs,
		name:     name,
		openMode: openMode,
	}
	if openMode&os.O_TRUNC != 0 {
		node.buf = []byte{}
	}

	if !writable(openMode) {
		if node.buf == nil {
			r, err := memfs.openContents(node)
			if err != nil {
				return nil, fmt.Errorf("opening %q: %w", name, err)
			}
			m.r = r
		}
		return m, nil
	}

	if err := memfs.bufferContents(node); err != nil {
		return nil, fmt.Errorf("opening %q: %w", name, err)
	}
	if openMode&os.O_APPEND != 0 {
		m.offset = int64(len(node.buf))
	}
	return m, nil
}

func (f *memFile) Stat() (fs.FileInfo, error) {
	if f.node == nil || f.fs == nil {
		return nil, fs.ErrClosed
	}
	return f.fs.Stat(f.name)
}

func (f *memFile) Close() error {
	if f.node == nil || f.fs == nil {
		return fs.ErrClosed
	}
	var err error
	if f.r != nil {
		err = f.r.Close()
	}
	f.fs = nil
	f.node = nil
	f.r = nil
	return err
}

func (f *memFile) Read(b []byte) (int, error) {
	if f.node == nil || f.fs == nil {
		return 0, fs.ErrClosed
	}
	if f.node.buf == nil {
		n, err := f.r.Read(b)
		f.offset += int64(n)
		return n, err
	}
	if f.offset >= int64(len(f.node.buf)) {
		return 0, io.EOF
	}
	n := copy(b, f.node.buf[f.offset:])
	f.offset += int64(n)
	return n, nil
}

func (f *memFile) ReadAt(p []byte, off int64) (n int, err error) {
	if f.node == nil || f.fs == nil {
		return 0, fs.ErrClosed
	}
	if f.node.buf == nil {
		if r, ok := f.r.(io.ReaderAt); ok {
			return r.ReadAt(p, off)
		}
		return 0, fs.ErrInvalid
	}
	return bytes.NewReader(f.node.buf).ReadAt(p, off)
}

func (f *memFile) Seek(offset int64, whence int) (int64, error) {
	if f.node == nil || f.fs == nil {
		return 0, fs.ErrClosed
	}
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		offset += f.offset
	case io.SeekEnd:
		if f.node.buf != nil {
			offset += int64(len(f.node.buf))
		} else {
			offset += f.node.size
		}
	default:
		return 0, errors.New("invalid whence")
	}
	if offset < 0 {
		return 0, errors.New("negative seek offset")
	}
	if f.node.buf == nil {
		r, ok := f.r.(io.Seeker)
		if !ok {
			return 0, fs.ErrInvalid
		}
		pos, err := r.Seek(offset, io.SeekStart)
		if err != nil {
			return pos, err
		}
		offset = pos
	}
	f.offset = offset
	return f.offset, nil
}

func (f *memFile) Write(p []byte) (n int, err error) {
	if f.node == nil || f.fs == nil {
		return 0, fs.ErrClosed
	}
	if !writable(f.openMode) {
		return 0, fmt.Errorf("write %s: file not opened for writing", f.name)
	}
	if f.offset+int64(len(p)) > int64(len(f.node.buf)) {
		f.node.buf = append(f.node.buf[:f.offset], p...)
	} else {
		copy(f.node.buf[f.offset:], p)
	}
	f.offset += int64(len(p))
	return len(p), nil
}

type node struct {
	mode         fs.FileMode
	uid, gid     int
	dir          bool
	name         string
	modTime      time.Time
	linkTarget   string
	linkCount    int // extra links, so 0 means a single pointer. O-based, like most compuuter counting systems.
	major, minor uint32
	children     map[string]*node
	mu           sync.Mutex
	xattrs       map[string][]byte

	hardlinks map[string]*tar.Header

	digest cas.Digest
	size   int64

	// Legacy sources use APK checksums for comparisons without opening content.
	source   *fileSource
	checksum []byte

	// A non-nil buf is authoritative, including when empty.
	buf []byte

	// pkg is the package that installed this file, if any.
	pkg *apk.Package
}

type fileSource struct {
	fs   fs.FS
	name string
}

type blobReader struct {
	*io.SectionReader
}

func (blobReader) Close() error { return nil }

func (m *memFS) openContents(n *node) (io.ReadCloser, error) {
	if n.buf != nil {
		return blobReader{io.NewSectionReader(bytes.NewReader(n.buf), 0, int64(len(n.buf)))}, nil
	}
	if !n.mode.IsRegular() {
		return blobReader{io.NewSectionReader(bytes.NewReader(nil), 0, 0)}, nil
	}
	if n.source != nil {
		return n.source.fs.Open(n.source.name)
	}
	r, err := m.blobs.OpenBlob(n.digest)
	if err != nil {
		return nil, err
	}
	return blobReader{r}, nil
}

func (m *memFS) bufferContents(n *node) error {
	if n.buf != nil {
		return nil
	}
	r, err := m.openContents(n)
	if err != nil {
		return err
	}
	defer r.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	n.buf = b
	return nil
}

func (n *node) fileInfo(parent, name string) fs.FileInfo {
	return &memFileInfo{
		node:   n,
		name:   name,
		parent: parent,
	}
}

type memFileInfo struct {
	*node
	name   string
	parent string
}

func (m *memFileInfo) Name() string {
	return m.name
}

func (m *memFileInfo) Size() int64 {
	if m.buf != nil {
		return int64(len(m.buf))
	}
	return m.size
}

func (m *memFileInfo) Mode() fs.FileMode {
	return m.mode
}

func (m *memFileInfo) ModTime() time.Time {
	return m.modTime
}

func (m *memFileInfo) IsDir() bool {
	return m.dir
}

func (m *memFileInfo) Sys() any {
	name := path.Join(m.parent, m.name)
	th := &tar.Header{
		Name: name,
		Mode: int64(m.mode),
		Uid:  m.uid,
		Gid:  m.gid,
	}

	// Preserve hardlink info if we have it.
	if hl, ok := m.hardlinks[name]; ok {
		th.Typeflag = hl.Typeflag
		th.Linkname = hl.Linkname
	}

	return th
}

// This is a bit janky, but we need a way to know who owns this.
func (m *memFileInfo) Package() *apk.Package {
	return m.pkg
}
