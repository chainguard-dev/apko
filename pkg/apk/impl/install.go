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
	"bytes"
	"compress/gzip"
	"crypto/sha1" // nolint:gosec // this is what apk tools is using
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// writeOneFile writes one file from the APK given the tar header and tar reader.
func (a *APKImplementation) writeOneFile(header *tar.Header, r io.Reader, allowOverwrite bool) error {
	// check if the file exists; allow override if the origin i
	if _, err := a.fs.Stat(header.Name); err == nil {
		if !allowOverwrite {
			// get the sum of the file, so we can compare it to the new file
			w := sha1.New() //nolint:gosec // this is what apk tools is using
			f, err := a.fs.Open(header.Name)
			if err != nil {
				return fmt.Errorf("unable to open existing file to calculate sum %s: %w", header.Name, err)
			}
			if _, err := io.Copy(w, f); err != nil {
				return fmt.Errorf("unable to calculate sum of existing file %s: %w", header.Name, err)
			}
			return FileExistsError{Path: header.Name, Sha1: w.Sum(nil)}
		}
		// allowOverwrite, so remove the file
		if err := a.fs.Remove(header.Name); err != nil {
			return fmt.Errorf("unable to remove existing file %s: %w", header.Name, err)
		}
	}
	f, err := a.fs.OpenFile(header.Name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, header.FileInfo().Mode())
	if err != nil {
		return fmt.Errorf("error creating file %s: %w", header.Name, err)
	}
	defer f.Close()

	if _, err := io.CopyN(f, r, header.Size); err != nil {
		return fmt.Errorf("unable to write content for %s: %w", header.Name, err)
	}
	// override one of the
	return nil
}

// installAPKFiles install the files from the APK and return the list of installed files
// and their permissions. Returns a tar.Header because it is a convenient existing
// struct that has all of the fields we need.
func (a *APKImplementation) installAPKFiles(gzipIn io.Reader, origin string) ([]tar.Header, error) {
	var files []tar.Header
	gr, err := gzip.NewReader(gzipIn)
	if err != nil {
		return nil, err
	}
	tmpDir, err := os.MkdirTemp("", "apk-install")
	if err != nil {
		return nil, fmt.Errorf("unable to create temporary directory for unpacking an apk: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	// per https://git.alpinelinux.org/apk-tools/tree/src/extract_v2.c?id=337734941831dae9a6aa441e38611c43a5fd72c0#n120
	//  * APKv1.0 compatibility - first non-hidden file is
	//  * considered to start the data section of the file.
	//  * This does not make any sense if the file has v2.0
	//  * style .PKGINFO
	var startedDataSection bool
	tr := tar.NewReader(gr)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		// if it was a hidden file and not a directory and we have not yet started the data section,
		// so skip this file
		if !startedDataSection && header.Name[0] == '.' && !strings.Contains(header.Name, "/") {
			continue
		}
		// whatever it is now, it is in the data section
		startedDataSection = true

		switch header.Typeflag {
		case tar.TypeDir:
			// special case, if the target already exists, and it is a symlink to a directory, we can accept it as is
			// otherwise, we need to create the directory.
			if fi, err := a.fs.Stat(header.Name); err == nil && fi.Mode()&os.ModeSymlink != 0 {
				if target, err := a.fs.Readlink(header.Name); err == nil {
					if fi, err = a.fs.Stat(target); err == nil && fi.IsDir() {
						// "break" rather than "continue", so that any handling outside of this switch statement is processed
						break
					}
				}
			}
			if err := a.fs.MkdirAll(header.Name, header.FileInfo().Mode().Perm()); err != nil {
				return nil, fmt.Errorf("error creating directory %s: %w", header.Name, err)
			}
		case tar.TypeReg:
			// we need to calculate the checksum of the file, and then pass it to the writeOneFile,
			// so we save it to a tempdir and then remove it
			f, err := os.CreateTemp(tmpDir, "apk-file")
			if err != nil {
				return nil, fmt.Errorf("error creating temporary file: %w", err)
			}

			// we need to calculate the checksum of the file while reading it
			w := sha1.New() //nolint:gosec // this is what apk tools is using
			tee := io.TeeReader(tr, w)
			if _, err := io.Copy(f, tee); err != nil {
				return nil, fmt.Errorf("error copying file %s: %w", header.Name, err)
			}
			offset, err := f.Seek(0, io.SeekStart)
			if err != nil {
				return nil, fmt.Errorf("error seeking to start of temp file for %s: %w", header.Name, err)
			}
			if offset != 0 {
				return nil, fmt.Errorf("error seeking to start of temp file for %s: offset is %d", header.Name, offset)
			}
			checksum := w.Sum(nil)

			if err := a.writeOneFile(header, f, false); err != nil {
				// if the error is something other than the file exists, return the error
				var fileExistsError FileExistsError
				if !errors.As(err, &fileExistsError) || origin == "" {
					return nil, err
				}
				// if the two files are identical, no need to overwrite, but we will keep the first one
				// that wrote it, which might be the base system or an earlier package
				if bytes.Equal(checksum, fileExistsError.Sha1) {
					continue
				}

				// they are not identical,
				// compare the origin of the package that we are installing now, to the origin of the package
				// that provided the file. If the origins are the same, then we can allow the
				// overwrite. Otherwise, we need to return an error.
				installed, err := a.GetInstalled()
				if err != nil {
					return nil, fmt.Errorf("unable to get list of installed packages and files: %w", err)
				}
				// go through each installed, looking for those that match our origin
				var found bool
				for _, pkg := range installed {
					// if it is not the same origin, we are not interested
					if pkg.Origin != origin {
						continue
					}
					// matched the origin, so look for the file we are installing
					for _, file := range pkg.Files {
						if file.Name == header.Name {
							found = true
							break
						}
					}
					if found {
						break
					}
				}
				if !found {
					return nil, fmt.Errorf("unable to install file over existing one, different contents: %s", header.Name)
				}
				// it was found in a package with the same origin, so just overwrite

				// if we get here, it had the same origin so even if different, we are allowed to overwrite the file
				if err := a.writeOneFile(header, f, true); err != nil {
					return nil, err
				}
			}
			// we need to save this somewhere. The output expects []tar.Header, so we need to override that.
			// Reusing a field should be good enough, provided that we know it is not getting in the way of
			// anything downstream. Since we know it is not, this is good enough.
			if header.PAXRecords == nil {
				header.PAXRecords = make(map[string]string)
			}
			// apk installed db uses this format
			header.PAXRecords[paxRecordsChecksumKey] = fmt.Sprintf("Q1%s", base64.StdEncoding.EncodeToString(checksum))
		case tar.TypeSymlink:
			// some underlying filesystems and some memfs that we use in tests do not support symlinks.
			// attempt it, and if it fails, just copy it.
			// if it already exists, pointing to the same target, we can ignore it
			if target, err := a.fs.Readlink(header.Name); err == nil && target == header.Linkname {
				continue
			}
			if err := a.fs.Symlink(header.Linkname, header.Name); err != nil {
				return nil, fmt.Errorf("unable to install symlink from %s -> %s: %w", header.Name, header.Linkname, err)
			}
		case tar.TypeLink:
			if err := a.fs.Link(header.Linkname, header.Name); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unsupported file type %s %v", header.Name, header.Typeflag)
		}
		files = append(files, *header)
	}

	return files, nil
}
