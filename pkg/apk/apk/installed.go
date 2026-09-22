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

package apk

import (
	"archive/tar"
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"chainguard.dev/apko/pkg/apk/types"
)

type InstalledPackage struct {
	Package
	Files []tar.Header
}

// getInstalledPackages get list of installed packages
func (a *APK) GetInstalled() ([]*InstalledPackage, error) {
	installedFile, err := a.fs.Open(installedFilePath)
	if err != nil {
		return nil, fmt.Errorf("could not open installed file in %s at %s: %w", a.fs, installedFilePath, err)
	}
	defer installedFile.Close()
	return ParseInstalled(installedFile)
}

// AddInstalledPackage add a package to the list of installed packages and returns
// the _incremental_ diff installing the package had on the idb file.
func (a *APK) AddInstalledPackage(pkg *Package, files []tar.Header) ([]byte, error) {
	// A record with an empty P: value is written without complaint and then
	// discarded wholesale by ParseInstalled, which gates on pkg.Name != "". The
	// package's files are left in the image belonging to no package at all, and
	// absent from the generated SBOM. Refuse to write a record we cannot read
	// back: at best it vanishes silently, and nothing downstream can tell that
	// from a package that was never installed.
	// A record written after a failed install would be built from an ownership
	// map that still credits files to a package with no record of its own, so it
	// could omit files that are really present. See abortInstalls.
	if err := a.installAborted(); err != nil {
		return nil, err
	}

	if pkg.Name == "" {
		return nil, MalformedPackageError{Field: "name", Err: ErrEmptyName}
	}

	// Validate before opening the file, so a rejected package cannot leave a
	// partially written record behind. Entry names are written into the database
	// verbatim as F: and R: lines, so a newline would let the package forge
	// additional records. This guards the sink itself, since AddInstalledPackage
	// is exported and is consumed as a library.
	//
	// Index rather than value range: a tar.Header is around 250 bytes, which is
	// more to copy per entry than reading one field off it costs.
	for i := range files {
		if err := validateRecordedEntryName(pkg.Name, files[i].Name); err != nil {
			return nil, err
		}
	}

	// sort the files by directory
	sortedFiles := cleanTarHeaders(files)
	// package lines
	pkgLines := PackageToInstalled(pkg)
	// file lines
	topDirNeeded := true
	for _, f := range sortedFiles {
		// Same invariant as the empty-name refusal above: don't write a record
		// we cannot read back. parseInstalledPerms range-checks the owner on an
		// "M:"/"a:" line, so an out-of-range uid here would not merely be wrong,
		// it would abort the read of the whole database -- and
		// hasUsrMergeBaseImage swallows that error and picks the wrong layout.
		if err := checkOwner(&f); err != nil {
			return nil, fmt.Errorf("refusing to record ownership for package %q: %w: "+
				"the installed database cannot express it and the resulting record "+
				"would make the whole database unreadable", pkg.Name, err)
		}

		perm := f.Mode & 0o7777
		user := f.Uid
		group := f.Gid

		if f.Typeflag == tar.TypeDir {
			dirName := strings.TrimSuffix(f.Name, fmt.Sprintf("%c", filepath.Separator))
			// The database spells the top-level directory as a bare "F:" with no
			// value. An entry whose name is nothing but separators denotes that
			// same directory, so normalise every spelling of it to the marker
			// rather than emitting "F:/" or "F://" for some of them.
			if strings.Trim(dirName, "/") == "" {
				dirName = ""
			}
			// ParseInstalled rejects an "M:" line following the bare marker
			// ("M entry cannot be associated with top level dir"), and that
			// error aborts the whole read, so the record would take the entire
			// database down rather than merely being wrong. A root entry with
			// default ownership and mode emits no M: line and is representable,
			// so only the non-default case has to be refused.
			if dirName == "" && (perm != 0o755 || user != 0 || group != 0) {
				return nil, fmt.Errorf("refusing to record ownership or permissions for the "+
					"top-level directory of package %q (entry %q, mode %04o, uid %d, gid %d): "+
					"the installed database cannot express them and the resulting record "+
					"would make the whole database unreadable", pkg.Name, f.Name, perm, user, group)
			}
			pkgLines = append(pkgLines, fmt.Sprintf("F:%s", dirName))
			if perm != 0o755 || user != 0 || group != 0 {
				pkgLines = append(pkgLines, fmt.Sprintf("M:%d:%d:%04o", user, group, perm))
			}
			topDirNeeded = false
		} else {
			if topDirNeeded {
				pkgLines = append(pkgLines, "F:")
				topDirNeeded = false
			}
			pkgLines = append(pkgLines, fmt.Sprintf("R:%s", filepath.Base(f.Name)))
			if perm != 0o644 || user != 0 || group != 0 {
				pkgLines = append(pkgLines, fmt.Sprintf("a:%d:%d:%04o", user, group, perm))
			}
			if f.PAXRecords != nil {
				if checksum := f.PAXRecords[paxRecordsChecksumKey]; checksum != "" {
					if !strings.HasPrefix(checksum, "Q1") {
						hexsum, err := hex.DecodeString(checksum)
						if err != nil {
							return nil, err
						}
						checksum = "Q1" + base64.StdEncoding.EncodeToString(hexsum)
					}
					pkgLines = append(pkgLines, fmt.Sprintf("Z:%s", checksum))
				}
			}
		}
	}
	// Final backstop on the record itself. Entry names are validated above, but
	// they are not the only attacker-influenced data rendered into these lines:
	// PackageToInstalled writes package metadata verbatim, and the Z: checksum
	// line passes a PAX record through unchanged for entry types whose checksum
	// is not recomputed. Rather than enumerate every field, assert the invariant
	// the format actually depends on -- one record per line, records separated by
	// a blank line -- so that any present or future field which acquires an
	// embedded newline fails here instead of silently forging a record.
	for _, line := range pkgLines {
		if types.ContainsNewline(line) {
			return nil, MalformedPackageError{
				Package: pkg.Name,
				Field:   recordToken(line),
				Value:   line,
				Err:     ErrEmbeddedNewline,
			}
		}
	}

	// Only now that the whole record is built and validated do we open the file,
	// so that no failure above can leave a created-but-empty database or a torn
	// record behind. Be sure to open in append mode so we add to the end.
	installedFile, err := a.fs.OpenFile(installedFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("could not open installed file at %s: %w", installedFilePath, err)
	}
	defer installedFile.Close()

	// write to installed file
	b := []byte(strings.Join(pkgLines, "\n") + "\n\n")
	if _, err := installedFile.Write(b); err != nil {
		return nil, err
	}
	return b, nil
}

// isInstalledPackage check if a specific package is installed
func (a *APK) isInstalledPackage(pkg string) (bool, error) {
	installedPackages, err := a.GetInstalled()
	if err != nil {
		return false, err
	}
	for _, installedPkg := range installedPackages {
		if installedPkg.Name == pkg {
			return true, nil
		}
	}
	return false, nil
}

// updateScriptsTar insert the scripts into the tarball
func (a *APK) updateScriptsTar(pkg *Package, controlData io.Reader, sourceDateEpoch *time.Time) error {
	tr := tar.NewReader(controlData)
	fi, err := a.fs.Stat(scriptsFilePath)
	if err != nil {
		return fmt.Errorf("unable to stat scripts file: %w", err)
	}
	scripts, err := a.fs.OpenFile(scriptsFilePath, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("unable to open scripts file %s: %w", scriptsFilePath, err)
	}
	defer scripts.Close()

	// only need to rewind if the file has tar in it
	if fi.Size() >= 1024 {
		if _, err = scripts.Seek(-1024, io.SeekEnd); err != nil {
			return fmt.Errorf("could not seek to end of tar file: %w", err)
		}
	}

	tw := tar.NewWriter(scripts)
	defer tw.Close()
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}

		// ignore .PKGINFO as it is not a script
		if header.Name == ".PKGINFO" { //nolint:goconst
			continue
		}

		// Ignore files that aren't executable.
		// This is mostly to ignore .melange.yaml files in the control section,
		// but apk itself has hardcoded list of scripts that we might want to do too.
		if header.FileInfo().Mode().Perm()&0555 != 0555 {
			continue
		}

		// Control-section names come out of the package archive just as the data
		// section's do, and this one is spliced into a name written into
		// usr/lib/apk/db/scripts.tar in the produced image, which apk-tools reads
		// and dispatches on by suffix. The install paths validate the data
		// section; the same check belongs here, and applies for the same reason:
		// nothing legitimate puts a control character in a script name.
		//
		// Rejecting here also fails earlier than tar.WriteHeader would. A name
		// containing a NUL is refused by the writer anyway, but only after the
		// package's data files have been installed and recorded.
		origName := header.Name
		if err := validateEntryName(pkg.Name, origName); err != nil {
			return err
		}
		header.Name = fmt.Sprintf("%s-%s.Q1%s%s", pkg.Name, pkg.Version, base64.StdEncoding.EncodeToString(pkg.Checksum), origName)

		// zero out timestamps for reproducibility
		if sourceDateEpoch != nil {
			header.ModTime = *sourceDateEpoch
			// we do not use AccessTime or ChangeTime because these are incompatible with USTar, which is required for apk.
			// See https://pkg.go.dev/archive/tar#Format for the capabilities of each format.
			// Setting them to time.Time{} or the epoch will cause them to be ignored.
			header.AccessTime = time.Time{}
			header.ChangeTime = time.Time{}
		}

		if err := tw.WriteHeader(header); err != nil {
			return fmt.Errorf("unable to write scripts header for %s: %w", header.Name, err)
		}
		if _, err := io.CopyN(tw, tr, header.Size); err != nil {
			return fmt.Errorf("unable to write content for %s: %w", header.Name, err)
		}
	}
	return nil
}

// readScriptsTar returns a reader for the current scripts.tar. It is up to the caller to close it.
func (a *APK) readScriptsTar() (io.ReadCloser, error) {
	return a.fs.Open(scriptsFilePath)
}

// updateTriggers insert the triggers into the triggers file
//
// The triggers database is line-oriented like the installed database, but it
// has no sink-side newline guard of its own. That is sound only because of the
// call graph: this function is unexported, its sole caller passes
// pkgInfo.Triggers straight from types.ParsePackageInfo, and that parser
// rejects an embedded newline in any field. Package carries no Triggers field,
// so a library consumer constructing one cannot reach here with unvalidated
// values. An exported wrapper, or a caller sourcing values from anywhere else,
// would need to validate them first.
func (a *APK) updateTriggers(pkg *Package, values []string) error {
	triggers, err := a.fs.OpenFile(triggersFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("unable to open triggers file %s: %w", triggersFilePath, err)
	}
	defer triggers.Close()

	for _, value := range values {
		if _, err := fmt.Fprintf(triggers, "Q1%s %s\n", base64.StdEncoding.EncodeToString(pkg.Checksum), value); err != nil {
			return fmt.Errorf("unable to write triggers file %s: %w", triggersFilePath, err)
		}
	}

	return nil
}

// readTriggers returns a reader for the current triggers. It is up to the caller to close it.
func (a *APK) readTriggers() (io.ReadCloser, error) {
	return a.fs.Open(triggersFilePath)
}

// maxInstalledLineLen bounds a single line of the installed database.
//
// bufio.Scanner defaults to 64KiB, which a legitimate record can exceed: a
// package with a few thousand dependencies renders one very long D: line. The
// bound still has to exist, because the reader is fed an attacker-influenced
// file and an unbounded line is an unbounded allocation. 1MiB is far above any
// plausible record and far below anything that matters for memory.
const maxInstalledLineLen = 1 << 20

// parseInstalled parses an installed file. It returns the installed packages.
func ParseInstalled(installed io.Reader) ([]*InstalledPackage, error) { //nolint:gocyclo
	if closer, ok := installed.(io.Closer); ok {
		defer closer.Close()
	}

	packages := []*InstalledPackage{}

	indexScanner := bufio.NewScanner(installed)
	indexScanner.Buffer(nil, maxInstalledLineLen)

	pkg := &InstalledPackage{}
	linenr := 1
	var lastDir, lastFile *tar.Header

	for indexScanner.Scan() {
		line := indexScanner.Text()
		if line == "" {
			if pkg.Name != "" {
				packages = append(packages, pkg)
			}
			pkg = &InstalledPackage{}
			lastDir = nil
			lastFile = nil
			continue
		}

		if len(line) < 2 {
			return nil, fmt.Errorf("cannot parse line %d: expected \"<token>:<value>\", saw %q", linenr, line)
		}
		if line[1:2] != ":" {
			return nil, fmt.Errorf("cannot parse line %d: expected \":\" in not found", linenr)
		}

		token := line[:1]
		val := line[2:]

		switch token {
		case "P":
			pkg.Name = val
		case "V":
			pkg.Version = val
		case "A":
			pkg.Arch = val
		case "L":
			pkg.License = val
		case "T":
			pkg.Description = val
		case "o":
			pkg.Origin = val
		case "m":
			pkg.Maintainer = val
		case "U":
			pkg.URL = val
		case "D":
			pkg.Dependencies = strings.Split(val, " ")
		case "p":
			pkg.Provides = strings.Split(val, " ")
		case "r":
			pkg.Replaces = strings.Split(val, " ")
		case "c":
			pkg.RepoCommit = val
		case "t":
			i, err := strconv.ParseInt(val, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("cannot parse build time %s: %w", val, err)
			}
			pkg.BuildDate = i
			pkg.BuildTime = time.Unix(i, 0).UTC()
		case "i":
			pkg.InstallIf = strings.Split(val, " ")
		case "S":
			size, err := strconv.ParseUint(val, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("cannot parse size field %s: %w", val, err)
			}
			pkg.Size = size
		case "I":
			installedSize, err := strconv.ParseUint(val, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("cannot parse installed size field %s: %w", val, err)
			}
			pkg.InstalledSize = installedSize
		case "k":
			priority, err := strconv.ParseUint(val, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("cannot parse provider priority field %s: %w", val, err)
			}
			pkg.ProviderPriority = priority
		case "C":
			// Handle SHA1 checksums:
			if strings.HasPrefix(val, "Q1") {
				checksum, err := base64.StdEncoding.DecodeString(val[2:])
				if err != nil {
					return nil, err
				}
				pkg.Checksum = checksum
			}
		case "F":
			lastDir = &tar.Header{
				Name:     val,
				Mode:     0o755,
				Uid:      0,
				Gid:      0,
				Typeflag: tar.TypeDir,
			}
			if val != "" {
				pkg.Files = append(pkg.Files, *lastDir)
			}
			lastFile = nil
		case "M":
			// directory perms if not 0o755
			if lastDir == nil {
				return nil, fmt.Errorf("cannot parse line %d: no directory specified when setting permissions", linenr)
			}
			if lastDir.Name == "" {
				return nil, fmt.Errorf("cannot parse line %d: M entry cannot be associated with top level dir", linenr)
			}
			uid, gid, perms, err := parseInstalledPerms(val)
			if err != nil {
				return nil, fmt.Errorf("cannot parse line %d: %w", linenr, err)
			}
			lastDir.Uid = uid
			lastDir.Gid = gid
			lastDir.Mode = perms
		case "R":
			fullpath := val
			if lastDir != nil {
				// Do not discard this error. sanitizeArchivePath returns ("", err)
				// when the joined path escapes its F: directory, so ignoring it
				// stored a file header with an empty Name -- which pkg/build then
				// fed back into AddInstalledPackage when building on this image as
				// a base. A traversal is not a legacy byte to be tolerated the way
				// a tab in a name is: apk-tools refuses ".." in an entry name
				// outright, and nothing legitimate produces one.
				var err error
				fullpath, err = sanitizeArchivePath(lastDir.Name, val)
				if err != nil {
					return nil, fmt.Errorf("cannot parse line %d: %w", linenr, err)
				}
			}
			lastFile = &tar.Header{
				Name: fullpath,
				Mode: 0o644,
				Uid:  0,
				Gid:  0,
			}
			pkg.Files = append(pkg.Files, *lastFile)
		case "a":
			// file perms if not 0o644
			if lastFile == nil {
				return nil, fmt.Errorf("cannot parse line %d: no file specified when setting permissions", linenr)
			}
			uid, gid, perms, err := parseInstalledPerms(val)
			if err != nil {
				return nil, fmt.Errorf("cannot parse line %d: %w", linenr, err)
			}
			lastFile.Uid = uid
			lastFile.Gid = gid
			lastFile.Mode = perms
		}

		linenr++
	}

	// bufio.Scanner reports a line longer than its buffer by stopping, not by
	// returning what it has. Without this check ParseInstalled returned the
	// packages accumulated so far and a nil error, so one over-long line quietly
	// erased every record after it -- and the SBOM built from this list said the
	// image contained fewer packages than it does.
	if err := indexScanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, fmt.Errorf("cannot parse line %d: line exceeds the maximum of %d bytes: %w",
				linenr, maxInstalledLineLen, err)
		}
		return nil, fmt.Errorf("reading the installed database: %w", err)
	}

	return packages, nil
}

func parseInstalledPerms(permString string) (uid, gid int, perms int64, err error) {
	permParts := strings.Split(permString, ":")
	if len(permParts) != 3 {
		return 0, 0, 0, fmt.Errorf("invalid permission string did not have 3 parts separated by colon: %s", permString)
	}
	uid, err = strconv.Atoi(permParts[0])
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid permission string uid was not an integer %s", permString)
	}
	// int64 cast: see checkOwner. uid is an int because it lands in
	// tar.Header.Uid, and math.MaxUint32 overflows an int where int is 32 bits.
	if uid < 0 || int64(uid) > math.MaxUint32 {
		return 0, 0, 0, fmt.Errorf("invalid permission string uid out of range %s", permString)
	}
	gid, err = strconv.Atoi(permParts[1])
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid permission string gid was not an integer %s", permString)
	}
	if gid < 0 || int64(gid) > math.MaxUint32 {
		return 0, 0, 0, fmt.Errorf("invalid permission string gid out of range %s", permString)
	}
	perms, err = strconv.ParseInt(permParts[2], 8, 64)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid permission string perms was not an int64 %s", permString)
	}
	return
}

// removeOrphanedEntries - remove all entries in a slice of tar.Header that cannot be reached.
//
//	An entry cannot be reached if there is no entry for it's parent directory.
//	As example, if /etc/hooks.d/pre-hook is a file, but there is no entry in
//	the slice for /etc or /etc/hooks.d, then /etc/hooks.d/pre-hook should be removed.
//
// https://github.com/chainguard-dev/apko/issues/1810
//
// Works in-place by rearranging the slice and returns the new length.
func removeOrphanedEntries(headers []tar.Header) int {
	if len(headers) == 0 {
		return 0
	}

	// Build a set of all directory paths (with and without trailing slashes)
	dirPaths := make(map[string]bool)
	for i := range headers {
		if headers[i].Typeflag == tar.TypeDir {
			// Add both versions of the path (with and without trailing slash)
			cleanPath := strings.TrimSuffix(headers[i].Name, "/")
			dirPaths[cleanPath] = true
			dirPaths[headers[i].Name] = true
		}
	}

	// Add root directory implicitly
	dirPaths[""] = true
	dirPaths["."] = true

	writeIndex := 0
	for readIndex := range headers {
		keep := true
		header := headers[readIndex]

		// For non-root entries, check if parent directories exist
		if header.Name != "" && header.Name != "." {
			parentPath := filepath.Dir(strings.TrimSuffix(header.Name, "/"))

			// Check parent hierarchy exists
			for parentPath != "" && parentPath != "." {
				if !dirPaths[parentPath] {
					keep = false
					break
				}
				parent := filepath.Dir(parentPath)
				if parent == parentPath {
					// filepath.Dir("/") is "/", so an absolute path would walk
					// here forever. A fixed point means the root has been
					// reached and the hierarchy is exhausted.
					break
				}
				parentPath = parent
			}
		}

		if keep {
			if writeIndex != readIndex {
				headers[writeIndex] = headers[readIndex]
			}
			writeIndex++
		}
	}

	return writeIndex
}

// cleanTarHeaders - return a copy of headers cleaned for apk installed database.
//
// Cleaning consists of
//  1. sorting
//  2. removing orphaned entries
func cleanTarHeaders(headers []tar.Header) []tar.Header {
	hCopy := make([]tar.Header, len(headers))
	copy(hCopy, headers)
	sort.SliceStable(hCopy,
		func(i, j int) bool {
			return pathCompare(
				hCopy[i].Name, hCopy[i].Typeflag == tar.TypeDir,
				hCopy[j].Name, hCopy[j].Typeflag == tar.TypeDir) < 0
		})
	newLen := removeOrphanedEntries(hCopy)
	return hCopy[:newLen]
}

// pathCompare - compare two paths for writing to apk installed database.
// within a given directory:
// 1. all non-directories (files, symlink, ...) will sort before directories
// 2. all non-directories and directories will be sorted within themselves.
func pathCompare(a string, aIsDir bool, b string, bIsDir bool) int {
	var n, result int
	aClean := filepath.Clean(a)
	bClean := filepath.Clean(b)
	if aClean == bClean {
		return 0
	}
	sep := fmt.Sprintf("%c", filepath.Separator)
	aToks := strings.Split(aClean, sep)
	bToks := strings.Split(bClean, sep)

	for n = 0; n < len(aToks)-1 && n < len(bToks)-1; n++ {
		result = strings.Compare(aToks[n], bToks[n])
		if result != 0 {
			return result
		}
	}

	// n represents the component that should be compared.
	// this token is a directory if
	//  1. it is the last token and the header is a directory ('lib' in /usr/local/lib)
	//  2. it is not the path's last token ('local' in /var/local/lib)
	aTokIsDir := n+1 < len(aToks) || aIsDir
	bTokIsDir := n+1 < len(bToks) || bIsDir

	if aTokIsDir == bTokIsDir {
		// both are directories or non-directories
		return strings.Compare(aToks[n], bToks[n])
	}
	// if a is not a dir, it goes before b
	if !aTokIsDir {
		return -1
	}
	return 1
}
