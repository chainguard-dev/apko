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
	"bufio"
	"cmp"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"path"
	"slices"
	"strings"
	"sync"
	"time"
)

var readerPool = sync.Pool{
	New: func() any {
		return bufio.NewReaderSize(nil, 1<<20)
	},
}

func pooledBufioReader(r io.Reader) *bufio.Reader {
	br := readerPool.Get().(*bufio.Reader)
	br.Reset(r)
	return br
}

// paxChecksumKey is the PAX record apk-tools uses for per-file checksums. It
// is present on essentially every entry, so it is stored decoded in a fixed
// field rather than in a per-entry map.
const paxChecksumKey = "APK-TOOLS.checksum.SHA1"

// Entry is a compact index of one tar header. A tar.Header stored by value
// costs ~1KB per file across three time.Times, an always-allocated PAX map,
// and a boxed FileInfo; an index over a large package multiplies that by
// thousands of files and lives as long as the package cache retains it. The
// header is reconstructed on demand via Header().
//
// Entry implements fs.FileInfo and fs.DirEntry with the same results as
// archive/tar's Header.FileInfo, so Stat and ReadDir never build a header.
type Entry struct {
	Offset int64

	name     string
	linkname string
	// dir is path.Dir(name).
	dir  string
	size int64
	// mtime is unix nanoseconds; mtimeZero marks a zero time.Time, which is
	// distinct from a genuine epoch timestamp.
	mtime     int64
	mtimeZero bool
	mode      int64
	// fileMode is Header.FileInfo().Mode(), computed once at index time so
	// the FileInfo view cannot drift from archive/tar.
	fileMode           fs.FileMode
	uid, gid           int
	devmajor, devminor int64
	typeflag           byte
	format             tar.Format
	uname, gname       string
	checksum           [20]byte // decoded paxChecksumKey record
	hasChecksum        bool
	// pax holds PAX records other than paxChecksumKey (xattrs, mostly).
	// It is nil for the vast majority of entries.
	pax map[string]string
}

func newEntry(hdr *tar.Header, offset int64) *Entry {
	e := &Entry{
		Offset:    offset,
		name:      hdr.Name,
		linkname:  hdr.Linkname,
		dir:       path.Dir(hdr.Name),
		size:      hdr.Size,
		mtimeZero: hdr.ModTime.IsZero(),
		mode:      hdr.Mode,
		fileMode:  hdr.FileInfo().Mode(),
		uid:       hdr.Uid,
		gid:       hdr.Gid,
		devmajor:  hdr.Devmajor,
		devminor:  hdr.Devminor,
		typeflag:  hdr.Typeflag,
		format:    hdr.Format,
		uname:     hdr.Uname,
		gname:     hdr.Gname,
	}
	if !e.mtimeZero {
		e.mtime = hdr.ModTime.UnixNano()
	}
	for k, v := range hdr.PAXRecords {
		// Only the lowercase form apk-tools writes is stored decoded, so that
		// hex.EncodeToString reproduces it exactly. hex.Decode would also
		// accept uppercase, which Header() could then not round-trip.
		if k == paxChecksumKey && len(v) == hex.EncodedLen(len(e.checksum)) && !strings.ContainsAny(v, "ABCDEF") {
			if _, err := hex.Decode(e.checksum[:], []byte(v)); err == nil {
				e.hasChecksum = true
				continue
			}
		}
		if e.pax == nil {
			e.pax = make(map[string]string, 1)
		}
		e.pax[k] = v
	}
	return e
}

// Header reconstructs the tar.Header this entry was built from. AccessTime
// and ChangeTime are not retained: apk-tools never writes them, and keeping
// them would cost two time.Times per entry. The checksum record is re-encoded
// only when it was the lowercase hex form that apk-tools writes; any other
// spelling is kept verbatim.
func (e *Entry) Header() tar.Header {
	hdr := tar.Header{
		Typeflag: e.typeflag,
		Name:     e.name,
		Linkname: e.linkname,
		Size:     e.size,
		Mode:     e.mode,
		Uid:      e.uid,
		Gid:      e.gid,
		Uname:    e.uname,
		Gname:    e.gname,
		Devmajor: e.devmajor,
		Devminor: e.devminor,
		Format:   e.format,
	}
	if !e.mtimeZero {
		hdr.ModTime = time.Unix(0, e.mtime)
	}
	if e.hasChecksum || e.pax != nil {
		hdr.PAXRecords = make(map[string]string, len(e.pax)+1)
		if e.hasChecksum {
			hdr.PAXRecords[paxChecksumKey] = hex.EncodeToString(e.checksum[:])
		}
		maps.Copy(hdr.PAXRecords, e.pax)
	}
	return hdr
}

// Checksum returns the decoded apk-tools per-file checksum, if present.
func (e *Entry) Checksum() ([]byte, bool) {
	if !e.hasChecksum {
		return nil, false
	}
	return e.checksum[:], true
}

func (e *Entry) Name() string {
	// Mirror archive/tar, which cleans directory names before taking the base
	// so a trailing slash does not yield an empty name.
	if e.IsDir() {
		return path.Base(path.Clean(e.name))
	}
	return path.Base(e.name)
}

func (e *Entry) Size() int64 {
	return e.size
}

func (e *Entry) Mode() fs.FileMode {
	return e.fileMode
}

func (e *Entry) Type() fs.FileMode {
	return e.fileMode.Type()
}

func (e *Entry) ModTime() time.Time {
	if e.mtimeZero {
		return time.Time{}
	}
	return time.Unix(0, e.mtime)
}

func (e *Entry) IsDir() bool {
	return e.fileMode.IsDir()
}

func (e *Entry) Info() (fs.FileInfo, error) {
	return e, nil
}

// Sys returns a *tar.Header, as archive/tar's FileInfo does. The header is
// built per call, so callers needing it repeatedly should hold the result.
func (e *Entry) Sys() any {
	hdr := e.Header()
	return &hdr
}

var (
	_ fs.FileInfo = (*Entry)(nil)
	_ fs.DirEntry = (*Entry)(nil)
)

type File struct {
	fsys  *FS
	sr    *io.SectionReader
	Entry *Entry
}

func (f *File) Stat() (fs.FileInfo, error) {
	return f.Entry, nil
}

func (f *File) Read(p []byte) (int, error) {
	return f.sr.Read(p)
}

func (f *File) Seek(offset int64, whence int) (int64, error) {
	return f.sr.Seek(offset, whence)
}

func (f *File) ReadAt(p []byte, off int64) (int, error) {
	return f.sr.ReadAt(p, off)
}

func (f *File) Close() error {
	return nil
}

type FS struct {
	ra    io.ReaderAt
	files []*Entry
	index map[string]int
	dirs  map[string][]fs.DirEntry
}

func (fsys *FS) Readlink(name string) (string, error) {
	i, ok := fsys.index[name]
	if !ok {
		return "", fs.ErrNotExist
	}

	e := fsys.files[i]

	switch e.typeflag {
	case tar.TypeSymlink, tar.TypeLink:
		return e.linkname, nil
	}

	return "", fmt.Errorf("Readlink(%q): file is not a link", name)
}

const maxHops = 64

// open follows symlinks up to [maxHops] times.
func (fsys *FS) open(name string, hops int) (fs.File, error) {
	if hops > maxHops {
		return nil, fmt.Errorf("Open(%q): chased too many (%d) symlinks", name, maxHops)
	}

	i, ok := fsys.index[name]
	if !ok {
		return nil, fs.ErrNotExist
	}

	e := fsys.files[i]

	switch e.typeflag {
	case tar.TypeSymlink, tar.TypeLink:
		link := e.linkname
		if path.IsAbs(link) {
			return fsys.open(link, hops+1)
		}

		return fsys.open(path.Join(e.dir, link), hops+1)
	}

	f := &File{
		fsys:  fsys,
		Entry: e,
	}

	f.sr = io.NewSectionReader(fsys.ra, e.Offset, e.size)

	return f, nil
}

// Open implements fs.FS.
func (fsys *FS) Open(name string) (fs.File, error) {
	return fsys.open(name, 0)
}

func (fsys *FS) Entries() []*Entry {
	return fsys.files
}

type root struct{}

func (r root) Name() string       { return "." }
func (r root) Size() int64        { return 0 }
func (r root) Mode() fs.FileMode  { return fs.ModeDir }
func (r root) ModTime() time.Time { return time.Unix(0, 0) }
func (r root) IsDir() bool        { return true }
func (r root) Sys() any           { return nil }

func (fsys *FS) Stat(name string) (fs.FileInfo, error) {
	if i, ok := fsys.index[name]; ok {
		return fsys.files[i], nil
	}

	// fs.WalkDir expects "." to return a root entry to bootstrap the walk.
	// If we didn't find it above, synthesize one.
	if name == "." {
		return root{}, nil
	}

	return nil, fs.ErrNotExist
}

func (fsys *FS) ReadDir(name string) ([]fs.DirEntry, error) {
	dirs, ok := fsys.dirs[name]
	if !ok {
		return []fs.DirEntry{}, nil
	}

	return dirs, nil
}

type countReader struct {
	r io.Reader
	n int64
}

func (cr *countReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	cr.n += int64(n)
	return n, err
}

func New(ra io.ReaderAt, size int64) (*FS, error) {
	fsys := &FS{
		ra:    ra,
		files: []*Entry{},
		index: map[string]int{},
		dirs:  map[string][]fs.DirEntry{},
	}

	// Number of entries in a given directory, so we know how large of a slice to allocate.
	dirCount := map[string]int{}

	// TODO: Consider caching this across builds.
	r := io.NewSectionReader(ra, 0, size)

	br := pooledBufioReader(r)
	defer readerPool.Put(br)

	cr := &countReader{br, 0}
	tr := tar.NewReader(cr)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		e := newEntry(hdr, cr.n)
		fsys.index[hdr.Name] = len(fsys.files)
		fsys.files = append(fsys.files, e)

		dirCount[e.dir]++
	}

	// Pre-generate the results of ReadDir so we don't allocate a ton if fs.WalkDir calls us.
	// TODO: Consider doing this lazily in a sync.Once the first time we see a ReadDir.
	for dir, count := range dirCount {
		fsys.dirs[dir] = make([]fs.DirEntry, 0, count)
	}

	for _, f := range fsys.files {
		fsys.dirs[f.dir] = append(fsys.dirs[f.dir], f)
	}

	for _, files := range fsys.dirs {
		slices.SortFunc(files, func(a, b fs.DirEntry) int {
			return cmp.Compare(a.Name(), b.Name())
		})
	}

	return fsys, nil
}

func (fsys *FS) UnderlyingReader() io.ReaderAt {
	return fsys.ra
}

func (fsys *FS) Close() error {
	if fsys == nil {
		return nil
	}

	closer, ok := fsys.ra.(io.Closer)
	if !ok {
		return nil
	}

	return closer.Close()
}
