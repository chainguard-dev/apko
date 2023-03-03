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

package impl

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gitlab.alpinelinux.org/alpine/go/repository"
)

type InstalledPackage struct {
	repository.Package
	Files []*tar.Header
}

// getInstalledPackages get list of installed packages
func (a *APKImplementation) GetInstalled() ([]*InstalledPackage, error) {
	installedFile, err := a.fs.Open(installedFilePath)
	if err != nil {
		return nil, fmt.Errorf("could not open installed file in %s at %s: %w", a.fs, installedFilePath, err)
	}
	defer installedFile.Close()
	return parseInstalled(installedFile)
}

// addInstalledPackage add a package to the list of installed packages
func (a *APKImplementation) addInstalledPackage(pkg *repository.Package, files []tar.Header) error {
	// be sure to open the file in append mode so we add to the end
	installedFile, err := a.fs.OpenFile(installedFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("could not open installed file at %s: %w", installedFilePath, err)
	}
	defer installedFile.Close()

	// sort the files by directory
	sort.Slice(files, func(i, j int) bool {
		if filepath.Dir(files[i].Name) < filepath.Dir(files[j].Name) {
			return true
		}
		if filepath.Dir(files[i].Name) > filepath.Dir(files[j].Name) {
			return false
		}
		return files[i].Name < files[j].Name
	})
	// package lines
	pkgLines := PackageToIndex(pkg)
	// file lines
	for _, f := range files {
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
		}
	}
	// write to installed file
	b := []byte("\n\n" + strings.Join(pkgLines, "\n") + "\n\n")
	if _, err := installedFile.Write(b); err != nil {
		return err
	}
	return nil
}

// isInstalledPackage check if a specific package is installed
func (a *APKImplementation) isInstalledPackage(pkg string) (bool, error) {
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
func (a *APKImplementation) updateScriptsTar(pkg *repository.Package, controlTarGz io.Reader, sourceDateEpoch *time.Time) error {
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
	// only need to rewind if the file has tar in it
	if fi.Size() >= 1024 {
		if _, err = scripts.Seek(-1024, io.SeekEnd); err != nil {
			return fmt.Errorf("could not seek to end of tar file: %w", err)
		}
	}

	defer scripts.Close()
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
		if header.Name == ".PKGINFO" {
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
func (a *APKImplementation) readScriptsTar() (io.ReadCloser, error) {
	return a.fs.Open(scriptsFilePath)
}

// updateTriggers insert the triggers into the triggers file
func (a *APKImplementation) updateTriggers(pkg *repository.Package, controlTarGz io.Reader) error {
	gz, err := gzip.NewReader(controlTarGz)
	if err != nil {
		return fmt.Errorf("unable to gunzip control tar file: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	triggers, err := a.fs.OpenFile(triggersFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("unable to open triggers file %s: %w", triggersFilePath, err)
	}
	defer triggers.Close()
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}

		// ignore .PKGINFO as it is not a script
		if header.Name != ".PKGINFO" {
			continue
		}

		b, err := io.ReadAll(tr)
		if err != nil {
			return fmt.Errorf("unable to read .PKGINFO from control tar.gz file: %w", err)
		}
		lines := strings.Split(string(b), "\n")
		for _, line := range lines {
			parts := strings.Split(line, "=")
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			if key != "triggers" {
				continue
			}
			if _, err := triggers.Write([]byte(fmt.Sprintf("%s %s", base64.StdEncoding.EncodeToString(pkg.Checksum), value))); err != nil {
				return fmt.Errorf("unable to write triggers file %s: %w", triggersFilePath, err)
			}
			break
		}
	}
	return nil
}

// readTriggers returns a reader for the current triggers. It is up to the caller to close it.
func (a *APKImplementation) readTriggers() (io.ReadCloser, error) {
	return a.fs.Open(triggersFilePath)
}

// parseInstalled parses an installed file. It returns the installed packages.
func parseInstalled(installed io.Reader) (packages []*InstalledPackage, err error) {
	if closer, ok := installed.(io.Closer); ok {
		defer closer.Close()
	}

	indexScanner := bufio.NewScanner(installed)

	pkg := &InstalledPackage{}
	linenr := 1
	var lastDir, lastFile *tar.Header

	for indexScanner.Scan() {
		line := indexScanner.Text()
		if len(line) == 0 {
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
		case "c":
			pkg.RepoCommit = val
		case "t":
			i, err := strconv.ParseInt(val, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("cannot parse build time %s: %w", val, err)
			}
			pkg.BuildTime = time.Unix(i, 0)
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
				Name: val,
				Mode: 0o755,
				Uid:  0,
				Gid:  0,
			}
			pkg.Files = append(pkg.Files, lastDir)
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
			pkg.Files = append(pkg.Files, lastFile)
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

	return
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
