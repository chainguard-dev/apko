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

package ldsocache

import (
	"bufio"
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unsafe"
)

const debug = false

func debugf(format string, args ...any) {
	if !debug {
		return
	}
	log.Printf(format, args...)
}

const ldsoMagic = "glibc-ld.so.cache"
const ldsoVersion = "1.1"
const ldsoExtensionMagic = 0xEAA42174

const (
	FlagANY                 uint32 = 0xffff
	FlagTYPEMASK            uint32 = 0x00ff
	FlagLIBC4               uint32 = 0x0000
	FlagELF                 uint32 = 0x0001
	FlagELFLIBC5            uint32 = 0x0002
	FlagELFLIBC6            uint32 = 0x0003
	FlagREQUIREDMASK        uint32 = 0xff00
	FlagSPARCLIB64          uint32 = 0x0100
	FlagX8664LIB64          uint32 = 0x0300
	FlagS390LIB64           uint32 = 0x0400
	FlagPOWERPCLIB64        uint32 = 0x0500
	FlagMIPS64LIBN32        uint32 = 0x0600
	FlagMIPS64LIBN64        uint32 = 0x0700
	FlagX8664LIBX32         uint32 = 0x0800
	FlagARMLIBHF            uint32 = 0x0900
	FlagAARCH64LIB64        uint32 = 0x0a00
	FlagARMLIBSF            uint32 = 0x0b00
	FlagMIPSLIB32NAN2008    uint32 = 0x0c00
	FlagMIPS64LIBN32NAN2008 uint32 = 0x0d00
	FlagMIPS64LIBN64NAN2008 uint32 = 0x0e00
	FlagRISCVFLOATABISOFT   uint32 = 0x0f00
	FlagRISCVFLOATABIDOUBLE uint32 = 0x1000
	FlagLARCHFLOATABISOFT   uint32 = 0x1100
	FlagLARCHFLOATABIDOUBLE uint32 = 0x1200
)

type LDSORawCacheHeader struct {
	Magic   [17]byte
	Version [3]byte

	NumLibs      uint32
	StrTableSize uint32

	Flags   uint8
	Unused0 [3]byte

	ExtOffset uint32

	Unused1 [3]uint32
}

type LDSORawCacheEntry struct {
	Flags uint32

	// Offsets in string table.
	Key   uint32
	Value uint32

	OSVersionNeeded uint32
	HWCapNeeded     uint64
}

type LDSOCacheEntry struct {
	Flags uint32

	Name string

	OSVersionNeeded uint32
	HWCapNeeded     uint64
}

type LDSOCacheExtensionHeader struct {
	Magic uint32
	Count uint32
}

type LDSOCacheExtensionSectionHeader struct {
	Tag    uint32
	Flags  uint32
	Offset uint32
	Size   uint32
}

type LDSOCacheExtensionSection struct {
	Header LDSOCacheExtensionSectionHeader
	Data   []byte
}

type LDSOCacheFile struct {
	Header     LDSORawCacheHeader
	Entries    []LDSOCacheEntry
	Extensions []LDSOCacheExtensionSection
}

// accepts a library name and returns its name and a version
// ex: "libfoo.so.1" -> "libfoo", "1"
// ex: "libbar.so" -> "libbar", ""
//
// returns an error if realname doesn't comply w/ the name scheme
func ParseLibFilename(realname string) (string, string, error) {
	var name string
	var ver string
	// ldconfig(8) says it "will look only at files that are named lib*.so*
	// (for regular shared objects) or ld-*.so* (for the dynamic loader itself).
	// Other files will be ignored.
	if !strings.HasPrefix(realname, "lib") && !strings.HasPrefix(realname, "ld-") {
		return "", "", fmt.Errorf("filename does not start with 'lib' or 'ld-': %s", realname)
	}
	if strings.HasSuffix(realname, ".so") {
		name = strings.TrimSuffix(realname, ".so")
		ver = ""
		return name, ver, nil
	}
	idx := strings.LastIndex(realname, ".so.")
	if idx < 1 {
		return "", "", fmt.Errorf("invalid library name: %s", realname)
	}
	name = realname[:idx]
	ver = realname[idx+len(".so."):]

	return name, ver, nil
}

// Scan `libdir` for shared libraries. Adds a new entry into `entryMap` for
// any that don't already have an entry there.
func AddLDSOCacheEntriesForDir(fsys fs.FS, libdir string, entryMap map[string]LDSOCacheEntry) error {
	var err error
	// fs.FS wants all file paths to be relative
	if filepath.IsAbs(libdir) {
		libdir, err = filepath.Rel("/", libdir)
		if err != nil {
			return err
		}
	}
	dirents, err := fs.ReadDir(fsys, libdir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}

	for _, dirent := range dirents {
		realname := dirent.Name()
		fullpath := filepath.Join(libdir, realname)
		mode := dirent.Type()
		isLink := (mode&fs.ModeSymlink != 0)

		if isLink {
			// Stat follows symlinks
			info, err := fs.Stat(fsys, fullpath)
			if err != nil {
				debugf("Warning: Could not stat %s\n", fullpath)
				continue
			}
			if !info.Mode().IsRegular() {
				debugf("DEBUG: Skipping %s, not a link to a regular file\n", fullpath)
				continue
			}
		}

		if !(mode.IsRegular() || isLink) {
			continue
		}
		libf, err := fsys.Open(fullpath)
		if err != nil {
			debugf("Warning: could not open %s\n", fullpath)
			continue
		}
		defer libf.Close()
		var libfReaderAt io.ReaderAt
		libfReaderAt, ok := libf.(io.ReaderAt)
		if !ok {
			// Ugly: Work around lack of ReaderAt support by
			// reading the entire file into memory
			buf, err := fs.ReadFile(fsys, fullpath)
			if err != nil {
				debugf("DEBUG: Unable to open %s\n", fullpath)
				continue
			}
			libf.Close()
			libfReaderAt = bytes.NewReader(buf)
		}
		elflibf, err := elf.NewFile(libfReaderAt)
		if err != nil {
			debugf("DEBUG: Unable to open %s as ELF\n", fullpath)
			continue
		}
		// FIXME: do we need to check for the ELF magic bytes?
		if elflibf.FileHeader.Type != elf.ET_DYN {
			continue
		}
		flags := uint32(0)
		flags |= FlagELF
		// FIXME: Shouldn't just assert this
		flags |= FlagELFLIBC6
		sonames, err := elflibf.DynString(elf.DT_SONAME)
		if err != nil {
			continue
		}
		switch elflibf.FileHeader.Machine {
		case elf.EM_X86_64:
			flags |= FlagX8664LIB64
		case elf.EM_AARCH64:
			flags |= FlagAARCH64LIB64
		// FIXME: Add other architectures
		default:
			return fmt.Errorf("unknown machine type")
		}
		libf.Close()

		// ldconfig will add an entry for a .so file even if it has
		// no SONAME. Observed with libR.so on Ubuntu.
		if len(sonames) == 0 && strings.HasSuffix(realname, ".so") {
			sonames = append(sonames, realname)
			debugf("DEBUG: %s has no SONAME, using filename as an SONAME\n", realname)
		}

		if len(sonames) == 0 && strings.HasSuffix(realname, ".so") {
			sonames = append(sonames, realname)
			debugf("DEBUG: %s has no DT_SONAME, using %s as an SONAME\n", realname, realname)
		}

		for _, soname := range sonames {
			fname, _, err := ParseLibFilename(soname)
			if err != nil {
				continue
			}
			linkname := fname + ".so"
			if realname != soname && realname != linkname {
				debugf("DEBUG: Skipping %s because it doesn't match soname %s or linkname %s\n", realname, soname, linkname)
				continue
			}
			_, ok := entryMap[realname]
			if ok {
				continue
			}
			entryMap[realname] = LDSOCacheEntry{
				// fullpath is relative to "/"
				Name:            filepath.Join("/", fullpath),
				Flags:           flags,
				OSVersionNeeded: 0,
				HWCapNeeded:     0,
			}
		}
	}
	return nil
}

func AddLDSOCacheEntriesForDirs(fsys fs.FS, libdirs []string) ([]LDSOCacheEntry, error) {
	entryMap := map[string]LDSOCacheEntry{}

	for _, libdir := range libdirs {
		err := AddLDSOCacheEntriesForDir(fsys, libdir, entryMap)
		if err != nil {
			return nil, err
		}
	}

	keys := make([]string, 0, len(entryMap))
	for k := range entryMap {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	entries := make([]LDSOCacheEntry, 0, len(entryMap))
	for _, k := range keys {
		entries = append(entries, entryMap[k])
	}

	return entries, nil
}

func BuildCacheFileForDirs(fsys fs.FS, libdirs []string) (*LDSOCacheFile, error) {
	entries, err := AddLDSOCacheEntriesForDirs(fsys, libdirs)
	if err != nil {
		return nil, err
	}

	header := LDSORawCacheHeader{
		Magic:   [17]byte([]byte(ldsoMagic)),
		Version: [3]byte([]byte(ldsoVersion)),
		NumLibs: (uint32)(len(entries)),
	}

	cf := LDSOCacheFile{
		Header:  header,
		Entries: entries,
	}

	return &cf, nil
}

// LoadCacheFile attempts to load a cache file from disk.  When
// successful, it returns an LDSOCacheFile pointer which contains
// all relevant information from the cache file.
func LoadCacheFile(path string) (*LDSOCacheFile, error) {
	bindata, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(bindata)

	// TODO(kaniini): Use binary.BigEndian for BE targets.
	header := LDSORawCacheHeader{}
	if err := binary.Read(r, binary.LittleEndian, &header); err != nil {
		return nil, err
	}

	rawlibs := []LDSORawCacheEntry{}
	for i := uint32(0); i < header.NumLibs; i++ {
		rawlib := LDSORawCacheEntry{}
		if err := binary.Read(r, binary.LittleEndian, &rawlib); err != nil {
			return nil, err
		}

		rawlibs = append(rawlibs, rawlib)
	}

	pos, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}

	// The string table is a series of nul-terminated C strings.
	strtable := make([]byte, header.StrTableSize)
	if _, err := r.Read(strtable); err != nil {
		return nil, err
	}

	// Now build the cache index itself.
	entries := []LDSOCacheEntry{}
	for _, rawlib := range rawlibs {
		entry := LDSOCacheEntry{
			Flags:           rawlib.Flags,
			OSVersionNeeded: rawlib.OSVersionNeeded,
			HWCapNeeded:     rawlib.HWCapNeeded,
		}

		name := extractShlibName(strtable, rawlib.Value-uint32(pos))
		entry.Name = name

		entries = append(entries, entry)
	}

	// Extension data begins at the next 4-byte aligned position.
	pos, err = r.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}

	// Align to nearest 4 byte boundary.
	alignedPos := (pos & -16) + 8
	_, err = r.Seek(alignedPos, io.SeekStart)
	if err != nil {
		return nil, err
	}

	file := LDSOCacheFile{
		Header:  header,
		Entries: entries,
	}

	// Check for a cache extension section.
	extHeader := LDSOCacheExtensionHeader{}
	if err := binary.Read(r, binary.LittleEndian, &extHeader); err != nil {
		return &file, nil
	}
	if extHeader.Magic != ldsoExtensionMagic {
		return &file, nil
	}

	// Parse the extension chunks we understand.
	sections := []*LDSOCacheExtensionSection{}
	for i := uint32(0); i < extHeader.Count; i++ {
		sectionHeader := LDSOCacheExtensionSectionHeader{}
		if err := binary.Read(r, binary.LittleEndian, &sectionHeader); err != nil {
			return &file, nil
		}

		section := &LDSOCacheExtensionSection{Header: sectionHeader}
		sections = append(sections, section)
	}

	// Load extension data.
	for _, section := range sections {
		pos, err = r.Seek(int64(section.Header.Offset), io.SeekStart)
		if err != nil {
			return &file, nil
		}
		if pos != int64(section.Header.Offset) {
			return &file, nil
		}

		section.Data = make([]byte, section.Header.Size)
		if _, err := r.Read(section.Data); err != nil {
			return &file, nil
		}
	}

	for _, section := range sections {
		file.Extensions = append(file.Extensions, *section)
	}

	return &file, nil
}

// extractShlibName extracts a shared library from the string table.
func extractShlibName(strtable []byte, startIdx uint32) string {
	subset := strtable[startIdx:]
	terminatorPos := bytes.IndexByte(subset, 0x0)

	if terminatorPos == -1 {
		return string(subset)
	}

	return string(subset[:terminatorPos])
}

func (cf *LDSOCacheFile) Write(w io.Writer) error {
	buf := &bytes.Buffer{}

	// Calculate the size of the file entry table for use
	// when calculating the file entry string table offsets.
	fileEntryTableSize := int(unsafe.Sizeof(LDSORawCacheHeader{}) + (uintptr(len(cf.Entries)) * unsafe.Sizeof(LDSORawCacheEntry{})))

	// Build the string table.
	lrcEntries := []LDSORawCacheEntry{}
	stringTable := []byte{}
	for _, lib := range cf.Entries {
		cursor := uint32(fileEntryTableSize) + uint32(len(stringTable))
		entry := []byte(lib.Name)
		entry = append(entry, byte(0x0))
		stringTable = append(stringTable, entry...)

		lrcEntry := LDSORawCacheEntry{
			Flags:           lib.Flags,
			Key:             cursor + uint32(len(filepath.Dir(lib.Name))+1),
			Value:           cursor,
			OSVersionNeeded: lib.OSVersionNeeded,
			HWCapNeeded:     lib.HWCapNeeded,
		}

		lrcEntries = append(lrcEntries, lrcEntry)
	}

	// Write the header section.
	cf.Header.NumLibs = uint32(len(lrcEntries))
	cf.Header.StrTableSize = uint32(len(stringTable))
	if err := cf.Header.Write(buf); err != nil {
		return err
	}

	// Write the file entry table.
	if err := binary.Write(buf, binary.LittleEndian, &lrcEntries); err != nil {
		return err
	}

	// Write the string table.
	if _, err := buf.Write(stringTable); err != nil {
		return err
	}

	pos := buf.Len()
	alignedPos := (pos & ^(0x10 - 1)) + 0x10

	pad := make([]byte, alignedPos-pos)
	if _, err := buf.Write(pad); err != nil {
		return err
	}

	// Write the extension sections.
	if len(cf.Extensions) > 0 {
		ehdr := LDSOCacheExtensionHeader{
			Magic: ldsoExtensionMagic,
			Count: uint32(len(cf.Extensions)),
		}

		if err := binary.Write(buf, binary.LittleEndian, &ehdr); err != nil {
			return err
		}

		for _, ext := range cf.Extensions {
			if err := binary.Write(buf, binary.LittleEndian, ext.Header); err != nil {
				return err
			}
		}

		for _, ext := range cf.Extensions {
			if _, err := buf.Write(ext.Data); err != nil {
				return err
			}
		}
	}

	_, err := io.Copy(w, buf)
	return err
}

// Write writes a header for a cache file to disk.
func (hdr *LDSORawCacheHeader) Write(w io.Writer) error {
	if err := binary.Write(w, binary.LittleEndian, hdr); err != nil {
		return err
	}

	return nil
}

// Parse an ld.so.conf file, following include directives and globs
// Return a slice of directory paths
func ParseLDSOConf(fsys fs.FS, ldsoconf string) ([]string, error) {
	conf, err := fsys.Open(ldsoconf)
	if err != nil {
		debugf("Warning: Could not open config file %s\n", ldsoconf)
		return nil, err
	}
	defer conf.Close()

	scanner := bufio.NewScanner(conf)
	libpaths := []string{}

	for scanner.Scan() {
		line := scanner.Text()
		line, _, _ = strings.Cut(line, "#") // remove comments
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		glob, isInclude := strings.CutPrefix(line, "include ")
		if isInclude {
			glob = strings.TrimSpace(glob)
			glob = strings.TrimLeft(glob, "/")
			matches, err := fs.Glob(fsys, glob)
			if err != nil {
				debugf("Warning: glob error in %s: %s", ldsoconf, glob)
				continue
			}
			if len(matches) == 0 {
				debugf("Warning: No matches for glob %s in %s\n", glob, ldsoconf)
			}

			for _, match := range matches {
				incpaths, err := ParseLDSOConf(fsys, match)
				if err != nil {
					debugf("Warning: Could not parse config file %s\n", match)
					continue
				}
				libpaths = append(libpaths, incpaths...)
			}
			return libpaths, nil
		}

		libpath := line
		if slices.Contains(libpaths, libpath) {
			debugf("Warning: Skipping %s because we've already seen it\n", libpath)
			continue
		}
		libpaths = append(libpaths, libpath)
	}
	return libpaths, scanner.Err()
}
