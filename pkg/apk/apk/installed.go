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
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/klauspost/compress/gzip"
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

// addInstalledPackage add a package to the list of installed packages
func (a *APK) AddInstalledPackage(pkg *Package, files []tar.Header) error {
	// be sure to open the file in append mode so we add to the end
	installedFile, err := a.fs.OpenFile(installedFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("could not open installed file at %s: %w", installedFilePath, err)
	}
	defer installedFile.Close()

	// sort the files by directory
	sortedFiles := sortTarHeaders(files)
	// package lines
	pkgLines := PackageToInstalled(pkg)
	// file lines
	for _, f := range sortedFiles {
		perm := f.Mode & 0777
		user := f.Uid
		group := f.Gid

		if f.Typeflag == tar.TypeDir {
			dirName := strings.TrimSuffix(f.Name, fmt.Sprintf("%c", filepath.Separator))
			pkgLines = append(pkgLines, fmt.Sprintf("F:%s", dirName))
			if perm != 0o755 || user != 0 || group != 0 {
				pkgLines = append(pkgLines, fmt.Sprintf("M:%d:%d:%04o", user, group, perm))
			}
		} else {
			pkgLines = append(pkgLines, fmt.Sprintf("R:%s", filepath.Base(f.Name)))
			if perm != 0o644 || user != 0 || group != 0 {
				pkgLines = append(pkgLines, fmt.Sprintf("a:%d:%d:%04o", user, group, perm))
			}
			if f.PAXRecords != nil {
				if checksum := f.PAXRecords[paxRecordsChecksumKey]; checksum != "" {
					if !strings.HasPrefix(checksum, "Q1") {
						hexsum, err := hex.DecodeString(checksum)
						if err != nil {
							return err
						}
						checksum = "Q1" + base64.StdEncoding.EncodeToString(hexsum)
					}
					pkgLines = append(pkgLines, fmt.Sprintf("Z:%s", checksum))
				}
			}
		}
	}
	// write to installed file
	b := []byte(strings.Join(pkgLines, "\n") + "\n\n")
	if _, err := installedFile.Write(b); err != nil {
		return err
	}
	return nil
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
func (a *APK) updateScriptsTar(pkg *Package, controlTarGz io.Reader, sourceDateEpoch *time.Time) error {
	gz, err := gzip.NewReader(controlTarGz)
	if err != nil {
		return fmt.Errorf("unable to gunzip control tar.gz file: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
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

		origName := header.Name
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

// TODO: We should probably parse control section on the first pass and reuse it.
func (a *APK) controlValue(controlTarGz io.Reader, want string) ([]string, error) {
	gz, err := gzip.NewReader(controlTarGz)
	if err != nil {
		return nil, fmt.Errorf("unable to gunzip control tar file: %w", err)
	}
	defer gz.Close()

	mapping, err := controlValue(gz, want)
	if err != nil {
		return nil, err
	}

	values, ok := mapping[want]
	if !ok {
		return []string{}, nil
	}
	return values, nil
}

// updateTriggers insert the triggers into the triggers file
func (a *APK) updateTriggers(pkg *Package, controlTarGz io.Reader) error {
	triggers, err := a.fs.OpenFile(triggersFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("unable to open triggers file %s: %w", triggersFilePath, err)
	}
	defer triggers.Close()

	values, err := a.controlValue(controlTarGz, "triggers")
	if err != nil {
		return fmt.Errorf("updating triggers for %s: %w", pkg.Name, err)
	}

	for _, value := range values {
		if _, err := triggers.Write([]byte(fmt.Sprintf("%s %s\n", base64.StdEncoding.EncodeToString(pkg.Checksum), value))); err != nil {
			return fmt.Errorf("unable to write triggers file %s: %w", triggersFilePath, err)
		}
	}

	return nil
}

// readTriggers returns a reader for the current triggers. It is up to the caller to close it.
func (a *APK) readTriggers() (io.ReadCloser, error) {
	return a.fs.Open(triggersFilePath)
}

// parseInstalled parses an installed file. It returns the installed packages.
func ParseInstalled(installed io.Reader) ([]*InstalledPackage, error) { //nolint:gocyclo
	if closer, ok := installed.(io.Closer); ok {
		defer closer.Close()
	}

	packages := []*InstalledPackage{}

	indexScanner := bufio.NewScanner(installed)

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

		if len(line) > 1 && line[1:2] != ":" {
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
			pkg.Files = append(pkg.Files, *lastDir)
			lastFile = nil
		case "M":
			// directory perms if not 0o755
			if lastDir == nil {
				return nil, fmt.Errorf("cannot parse line %d: no directory specified when setting permissions", linenr)
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
				fullpath, _ = sanitizeArchivePath(lastDir.Name, val)
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
	gid, err = strconv.Atoi(permParts[1])
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid permission string gid was not an integer %s", permString)
	}
	perms, err = strconv.ParseInt(permParts[2], 8, 64)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid permission string perms was not an int64 %s", permString)
	}
	return
}

// sortTarHeaders sorts tar headers by name. It ensures that all file children
// of a directory are listed immediately after the directory itself. This is to
// support lib/apk/db/installed, which lists full paths for directories, but
// only the basename for the files, so the last directory entry before a file
// must be the parent in which it sits.
func sortTarHeaders(headers []tar.Header) []tar.Header {
	var (
		// Create a tree with everything in it, where keys are full directory paths,
		// values are slice of full paths of children. (Every directory in the tree will
		// have its own key in the map.)
		directoryChildren = map[string][]string{}

		all = map[string]tar.Header{}
	)

	for _, header := range headers {
		// Use a cleaned name for map keys to ensure consistency with lookups later.
		cleanedName := filepath.Clean(header.Name)

		dir := filepath.Dir(cleanedName)
		directoryChildren[dir] = append(directoryChildren[dir], cleanedName)
		all[cleanedName] = header
	}

	// Map the directory entries (the keys in "directoryChildren") to a slice (and
	// sort them for determinism).
	var dirEntries = make([]string, 0, len(directoryChildren))
	for dir := range directoryChildren {
		dirEntries = append(dirEntries, dir)
	}
	sort.Strings(dirEntries)

	// We'll start with top-level directories, and then descend into their children
	// recursively.
	var topLevelDirs = make([]string, 0, len(dirEntries))
	for _, dir := range dirEntries {
		if filepath.Dir(dir) == "." {
			topLevelDirs = append(topLevelDirs, dir)
		}
	}

	sort.Strings(topLevelDirs)

	sorted := sortChildrenTarHeaders(directoryChildren, all, topLevelDirs)
	return sorted
}

func sortChildrenTarHeaders(directoryChildren map[string][]string, all map[string]tar.Header, children []string) []tar.Header {
	sort.Strings(children)

	// Non-directory type files need to be first.
	var sorted = make([]tar.Header, 0, len(children))
	for _, child := range children {
		header, ok := all[child]
		if !ok {
			continue
		}
		if header.Typeflag != tar.TypeDir {
			sorted = append(sorted, header)
		}
	}

	// Then directories.
	for _, child := range children {
		header, ok := all[child]
		if !ok {
			continue
		}
		if header.Typeflag == tar.TypeDir {
			sorted = append(sorted, header)

			// And their children.
			children, ok := directoryChildren[child]
			if !ok || len(children) == 0 {
				continue
			}

			sortedChildren := sortChildrenTarHeaders(directoryChildren, all, children)
			sorted = append(sorted, sortedChildren...)
		}
	}

	return sorted
}
