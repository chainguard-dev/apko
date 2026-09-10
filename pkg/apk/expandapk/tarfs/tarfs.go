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
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"slices"
	"strings"
	"sync"
	"time"
	"unique"
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

// Entry is a tar member with its full header. Entries are materialized from
// the resident index on request (see Entries and File.Entry), so callers pay
// for the header only while they hold one.
type Entry struct {
	Header tar.Header
	Offset int64

	dir string
	fi  fs.FileInfo
}

func (e Entry) Name() string {
	return e.fi.Name()
}

func (e Entry) Size() int64 {
	return e.Header.Size
}

func (e Entry) Type() fs.FileMode {
	return e.fi.Mode()
}

func (e Entry) Info() (fs.FileInfo, error) {
	return e.fi, nil
}

func (e Entry) IsDir() bool {
	return e.fi.IsDir()
}

const paxSchilyXattr = "SCHILY.xattr."

type paxRecord struct {
	key   unique.Handle[string]
	value string
}

// entry is the resident index record for one tar member. It holds what a
// tar.Header holds, laid out to avoid the per-member map and the duplicated
// strings that make a retained tar.Header expensive across many packages.
type entry struct {
	name     string
	linkname string
	dir      string
	uname    unique.Handle[string]
	gname    unique.Handle[string]
	size     int64
	offset   int64
	mode     int64
	modTime  time.Time
	devmajor int64
	devminor int64
	uid      int32
	gid      int32
	fileMode fs.FileMode
	format   int8
	typeflag byte
	pax      []paxRecord
	// times is set only when the header carries access or change times,
	// which apk packages almost never do.
	times *struct{ access, change time.Time }
}

func newEntry(hdr *tar.Header, offset int64) *entry {
	e := &entry{
		name:     hdr.Name,
		linkname: hdr.Linkname,
		dir:      path.Dir(hdr.Name),
		uname:    unique.Make(hdr.Uname),
		gname:    unique.Make(hdr.Gname),
		size:     hdr.Size,
		offset:   offset,
		mode:     hdr.Mode,
		modTime:  hdr.ModTime,
		devmajor: hdr.Devmajor,
		devminor: hdr.Devminor,
		uid:      int32(hdr.Uid),
		gid:      int32(hdr.Gid),
		fileMode: hdr.FileInfo().Mode(),
		format:   int8(hdr.Format),
		typeflag: hdr.Typeflag,
	}
	if !hdr.AccessTime.IsZero() || !hdr.ChangeTime.IsZero() {
		e.times = &struct{ access, change time.Time }{hdr.AccessTime, hdr.ChangeTime}
	}
	if len(hdr.PAXRecords) > 0 {
		e.pax = make([]paxRecord, 0, len(hdr.PAXRecords))
		for k, v := range hdr.PAXRecords {
			e.pax = append(e.pax, paxRecord{key: unique.Make(k), value: v})
		}
	}
	return e
}

// header rebuilds the tar.Header this entry was indexed from, including its
// PAX records and the Xattrs view archive/tar derives from them.
func (e *entry) header() tar.Header {
	hdr := tar.Header{
		Typeflag: e.typeflag,
		Name:     e.name,
		Linkname: e.linkname,
		Size:     e.size,
		Mode:     e.mode,
		Uid:      int(e.uid),
		Gid:      int(e.gid),
		Uname:    e.uname.Value(),
		Gname:    e.gname.Value(),
		ModTime:  e.modTime,
		Devmajor: e.devmajor,
		Devminor: e.devminor,
		Format:   tar.Format(e.format),
	}
	if e.times != nil {
		hdr.AccessTime, hdr.ChangeTime = e.times.access, e.times.change
	}
	if len(e.pax) > 0 {
		hdr.PAXRecords = make(map[string]string, len(e.pax))
		for _, r := range e.pax {
			k := r.key.Value()
			hdr.PAXRecords[k] = r.value
			// archive/tar still fills the deprecated Xattrs view alongside
			// PAXRecords; readers of either must see the same header.
			if r.value != "" && strings.HasPrefix(k, paxSchilyXattr) {
				if hdr.Xattrs == nil { //nolint:staticcheck // mirrors archive/tar
					hdr.Xattrs = make(map[string]string) //nolint:staticcheck // mirrors archive/tar
				}
				hdr.Xattrs[k[len(paxSchilyXattr):]] = r.value //nolint:staticcheck // mirrors archive/tar
			}
		}
	}
	return hdr
}

// view materializes the exported Entry for this record.
func (e *entry) view() *Entry {
	return &Entry{Header: e.header(), Offset: e.offset, dir: e.dir, fi: e}
}

// entry implements fs.FileInfo and fs.DirEntry with the same results as
// archive/tar's Header.FileInfo, so directory listings and Stat never need a
// materialized header.

func (e *entry) Name() string {
	if e.fileMode.IsDir() {
		return path.Base(path.Clean(e.name))
	}
	return path.Base(e.name)
}
func (e *entry) Size() int64                { return e.size }
func (e *entry) Mode() fs.FileMode          { return e.fileMode }
func (e *entry) Type() fs.FileMode          { return e.fileMode }
func (e *entry) ModTime() time.Time         { return e.modTime }
func (e *entry) IsDir() bool                { return e.fileMode.IsDir() }
func (e *entry) Info() (fs.FileInfo, error) { return e, nil }

// Sys matches archive/tar, which returns the *tar.Header behind a FileInfo.
func (e *entry) Sys() any {
	hdr := e.header()
	return &hdr
}

type File struct {
	fsys  *FS
	sr    *io.SectionReader
	Entry *Entry
}

func (f *File) Stat() (fs.FileInfo, error) {
	return f.Entry.fi, nil
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
	files []*entry
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
		Entry: e.view(),
	}

	f.sr = io.NewSectionReader(fsys.ra, e.offset, e.size)

	return f, nil
}

// Open implements fs.FS.
func (fsys *FS) Open(name string) (fs.File, error) {
	return fsys.open(name, 0)
}

// Entries returns every member in archive order, each with its full header.
// The slice is built on each call; hold it only as long as it is needed.
func (fsys *FS) Entries() []*Entry {
	entries := make([]*Entry, len(fsys.files))
	for i, e := range fsys.files {
		entries[i] = e.view()
	}
	return entries
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
		files: []*entry{},
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
		fsys.index[e.name] = len(fsys.files)
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
