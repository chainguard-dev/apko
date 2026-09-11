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
// the resident index on request, so callers pay for the header only while
// they hold one. Entries and Open each build a fresh Entry per call, and
// each materialization owns its maps, so a caller's mutation is private to
// it. Consumers that only need file metadata should prefer Stat or ReadDir,
// which serve the index directly and never build a header.
type Entry struct {
	Header tar.Header
	Offset int64

	fi fs.FileInfo
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

const (
	paxSchilyXattr = "SCHILY.xattr."
	// paxChecksumKey is the per-file checksum apk-tools records on nearly every
	// regular file. It is stored decoded rather than as a PAX record.
	paxChecksumKey = "APK-TOOLS.checksum.SHA1"
)

type paxRecord struct {
	key   unique.Handle[string]
	value string
}

// entry is the resident index record for one tar member. It holds what a
// tar.Header holds, laid out to avoid the per-member map and the duplicated
// strings that make a retained tar.Header expensive across many packages. It
// also implements fs.FileInfo and fs.DirEntry with the same results as
// archive/tar's Header.FileInfo, so Stat, ReadDir, and fs.WalkDir never
// materialize a header.
//
// Interning uname, gname, and PAX keys assumes the apk shape, where those
// repeat across every member (root, the checksum key). An archive of
// entirely distinct values gets no dedup, only the hashing cost.
type entry struct {
	name     string
	linkname string
	uname    unique.Handle[string]
	gname    unique.Handle[string]
	size     int64
	offset   int64
	mode     int64
	uid      int64
	gid      int64
	// mtime is the modification time as Unix nanoseconds. archive/tar builds
	// every ModTime with time.Unix, so time.Unix(0, mtime) reproduces it
	// exactly; a value that cannot, such as a zero time or one outside the
	// int64 nanosecond range, is kept whole in rare.mtime instead.
	mtime    int64
	fileMode fs.FileMode
	format   int8 // archive/tar's formatMax is 32
	typeflag byte
	hasPAX   bool
	// checksum holds the paxChecksumKey record decoded from its 40-character
	// lowercase hex form, which is what apk-tools writes. Any other spelling
	// stays in rare.pax verbatim so the header round-trips byte for byte.
	hasChecksum bool
	checksum    [sha1Size]byte
	// rare is nil for the typical apk member: a regular file or directory
	// with a checksum and nothing else unusual. It is allocated only for
	// the fields below, so the common record does not carry their width.
	rare *rareFields
}

// rareFields holds header state that most apk members do not have.
type rareFields struct {
	access, change     time.Time
	mtime              time.Time // set when entry.mtime cannot represent it
	hasMtime           bool
	devmajor, devminor int64
	pax                []paxRecord // PAX records other than the decoded checksum
}

const sha1Size = 20

// decodeChecksum reports the checksum bytes when v is exactly the lowercase
// hex encoding of a SHA-1, so that hex.EncodeToString reproduces v unchanged.
// It decodes by hand rather than through encoding/hex to avoid the two
// allocations (the []byte copy and the re-encoded string) on the hot path
// that runs for every member of every package.
func decodeChecksum(v string) ([sha1Size]byte, bool) {
	var sum [sha1Size]byte
	if len(v) != 2*sha1Size {
		return sum, false
	}
	for i := range sum {
		hi, ok1 := lowerHexNibble(v[2*i])
		lo, ok2 := lowerHexNibble(v[2*i+1])
		if !ok1 || !ok2 {
			return sum, false
		}
		sum[i] = hi<<4 | lo
	}
	return sum, true
}

func lowerHexNibble(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	}
	return 0, false
}

// newEntry indexes hdr at offset. uname and gname are the interned handles
// for hdr.Uname and hdr.Gname; the caller supplies them so it can skip the
// intern lookup when consecutive members share an owner, which in an apk is
// nearly always.
func newEntry(hdr *tar.Header, offset int64, uname, gname unique.Handle[string]) *entry {
	e := &entry{
		name:     hdr.Name,
		linkname: hdr.Linkname,
		uname:    uname,
		gname:    gname,
		size:     hdr.Size,
		offset:   offset,
		mode:     hdr.Mode,
		uid:      int64(hdr.Uid),
		gid:      int64(hdr.Gid),
		fileMode: hdr.FileInfo().Mode(),
		format:   int8(hdr.Format),
		typeflag: hdr.Typeflag,
	}
	// rare is allocated lazily so the check for each field costs nothing on
	// the members that have none of them.
	rare := func() *rareFields {
		if e.rare == nil {
			e.rare = &rareFields{}
		}
		return e.rare
	}
	// Checked by reconstruction, not by range: this is exactly what header()
	// will do, so it cannot disagree with it. Struct equality on purpose, not
	// Equal: the rebuilt header has to be the identical time.Time value,
	// including location, or DeepEqual against archive/tar's output fails.
	if n := hdr.ModTime.UnixNano(); time.Unix(0, n) == hdr.ModTime { //nolint:staticcheck // see above
		e.mtime = n
	} else {
		r := rare()
		r.mtime, r.hasMtime = hdr.ModTime, true
	}
	if !hdr.AccessTime.IsZero() || !hdr.ChangeTime.IsZero() {
		r := rare()
		r.access, r.change = hdr.AccessTime, hdr.ChangeTime
	}
	if hdr.Devmajor != 0 || hdr.Devminor != 0 {
		r := rare()
		r.devmajor, r.devminor = hdr.Devmajor, hdr.Devminor
	}
	// Keyed on nil, not length: archive/tar hands back a non-nil empty map
	// for a member preceded by a zero-record extended header.
	if hdr.PAXRecords != nil {
		e.hasPAX = true
		for k, v := range hdr.PAXRecords {
			if k == paxChecksumKey {
				if sum, ok := decodeChecksum(v); ok {
					e.hasChecksum, e.checksum = true, sum
					continue
				}
			}
			r := rare()
			r.pax = append(r.pax, paxRecord{key: unique.Make(k), value: v})
		}
	}
	return e
}

// dir is the directory the member lives in. path.Dir returns a prefix of
// the name for the paths archive/tar produces, so this does not allocate.
func (e *entry) dir() string {
	return path.Dir(e.name)
}

// modTime rebuilds the header's ModTime from whichever form holds it.
func (e *entry) modTime() time.Time {
	if r := e.rare; r != nil && r.hasMtime {
		return r.mtime
	}
	return time.Unix(0, e.mtime)
}

// header rebuilds the tar.Header this entry was indexed from, including its
// PAX records and the Xattrs view archive/tar derives from them. Every
// tar.Header field archive/tar populates has to be represented on entry and
// restored here, so a field added to tar.Header in a future Go release needs
// adding in both places.
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
		ModTime:  e.modTime(),
		Format:   tar.Format(e.format),
	}
	var pax []paxRecord
	if r := e.rare; r != nil {
		hdr.AccessTime, hdr.ChangeTime = r.access, r.change
		hdr.Devmajor, hdr.Devminor = r.devmajor, r.devminor
		pax = r.pax
	}
	if e.hasPAX {
		hdr.PAXRecords = make(map[string]string, len(pax)+1)
		if e.hasChecksum {
			hdr.PAXRecords[paxChecksumKey] = hex.EncodeToString(e.checksum[:])
		}
		for _, r := range pax {
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

// fill materializes the exported Entry for this record into dst.
func (e *entry) fill(dst *Entry) {
	*dst = Entry{Header: e.header(), Offset: e.offset, fi: e}
}

func (e *entry) Name() string {
	if e.fileMode.IsDir() {
		return path.Base(path.Clean(e.name))
	}
	return path.Base(e.name)
}
func (e *entry) Size() int64                { return e.size }
func (e *entry) Mode() fs.FileMode          { return e.fileMode }
func (e *entry) Type() fs.FileMode          { return e.fileMode }
func (e *entry) ModTime() time.Time         { return e.modTime() }
func (e *entry) IsDir() bool                { return e.fileMode.IsDir() }
func (e *entry) Info() (fs.FileInfo, error) { return e, nil }
func (e *entry) String() string             { return fs.FormatFileInfo(e) }

// Sys matches archive/tar, which returns the *tar.Header behind a FileInfo.
// Each call builds a new header, so a caller needing it more than once should
// hold the result rather than calling Sys again.
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

		return fsys.open(path.Join(e.dir(), link), hops+1)
	}

	// The File and its Entry share one allocation; the Entry is the exported
	// view a caller may read through File.Entry, so it has to exist at Open.
	fe := &struct {
		f File
		e Entry
	}{}
	e.fill(&fe.e)
	fe.f = File{
		fsys:  fsys,
		sr:    io.NewSectionReader(fsys.ra, e.offset, e.size),
		Entry: &fe.e,
	}
	return &fe.f, nil
}

// Open implements fs.FS.
func (fsys *FS) Open(name string) (fs.File, error) {
	return fsys.open(name, 0)
}

// Entries returns every member in archive order, each with its full header.
// The slice is built on each call; hold it only as long as it is needed.
func (fsys *FS) Entries() []*Entry {
	// One backing array for every Entry rather than an allocation each; the
	// caller holds the whole slice anyway.
	backing := make([]Entry, len(fsys.files))
	entries := make([]*Entry, len(fsys.files))
	for i, e := range fsys.files {
		e.fill(&backing[i])
		entries[i] = &backing[i]
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
	// Consecutive members almost always share an owner, so intern once per
	// run of equal names instead of hashing every header's uname and gname.
	lastUname, lastGname := "", ""
	uname, gname := unique.Make(""), unique.Make("")
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Uname != lastUname {
			lastUname, uname = hdr.Uname, unique.Make(hdr.Uname)
		}
		if hdr.Gname != lastGname {
			lastGname, gname = hdr.Gname, unique.Make(hdr.Gname)
		}
		e := newEntry(hdr, cr.n, uname, gname)
		fsys.index[e.name] = len(fsys.files)
		fsys.files = append(fsys.files, e)

		dirCount[e.dir()]++
	}

	// Pre-generate the results of ReadDir so we don't allocate a ton if fs.WalkDir calls us.
	// TODO: Consider doing this lazily in a sync.Once the first time we see a ReadDir.
	for dir, count := range dirCount {
		fsys.dirs[dir] = make([]fs.DirEntry, 0, count)
	}

	for _, f := range fsys.files {
		d := f.dir()
		fsys.dirs[d] = append(fsys.dirs[d], f)
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
