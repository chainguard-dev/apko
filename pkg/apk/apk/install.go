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
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // this is what apk tools is using
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"go.opentelemetry.io/otel"

	"chainguard.dev/apko/pkg/apk/internal/tarfs"
)

// writeOneFile writes one file from the APK given the tar header and tar reader.
func (a *APK) writeOneFile(header *tar.Header, r io.Reader, allowOverwrite bool) error {
	// check if the file exists; allow override if the origin i
	if _, err := a.fs.Stat(header.Name); err == nil {
		if !allowOverwrite {
			// get the sum of the file, so we can compare it to the new file
			w := sha1.New() //nolint:gosec // this is what apk tools is using
			f, err := a.fs.Open(header.Name)
			if err != nil {
				return fmt.Errorf("unable to open existing file to calculate sum %s: %w", header.Name, err)
			}
			defer f.Close()
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

// installRegularFile handles the various error modes of writing a regular file
func (a *APK) installRegularFile(header *tar.Header, tr *tar.Reader, tmpDir string, pkg *Package) (bool, error) {
	checksum, err := checksumFromHeader(header)
	if err != nil {
		return false, err
	}

	replaceMap := map[string]struct{}{}
	for _, r := range pkg.Replaces {
		replaceMap[r] = struct{}{}
	}

	var r io.Reader = tr

	if checksum == nil {
		// There was no checksum header, which is unexpected, but we can just recalculate it.

		w := sha1.New() //nolint:gosec // this is what apk tools is using
		tee := io.TeeReader(tr, w)

		// we need to calculate the checksum of the file, and then pass it to the writeOneFile,
		// so we save it to a tempdir and then remove it
		f, err := os.CreateTemp(tmpDir, "apk-file")
		if err != nil {
			return false, fmt.Errorf("error creating temporary file: %w", err)
		}

		if _, err := io.Copy(f, tee); err != nil {
			return false, fmt.Errorf("error copying file %s: %w", header.Name, err)
		}
		offset, err := f.Seek(0, io.SeekStart)
		if err != nil {
			return false, fmt.Errorf("error seeking to start of temp file for %s: %w", header.Name, err)
		}
		if offset != 0 {
			return false, fmt.Errorf("error seeking to start of temp file for %s: offset is %d", header.Name, offset)
		}
		checksum = w.Sum(nil)

		r = f
	}

	if err := a.writeOneFile(header, r, false); err != nil {
		// If the error is something other than the file exists, return the error.
		var fileExistsError FileExistsError
		if !errors.As(err, &fileExistsError) || pkg.Origin == "" {
			return false, err
		}

		// If the two files are identical, no need to overwrite, but we will keep the first one
		// that wrote it, which might be the base system or an earlier package.
		if bytes.Equal(checksum, fileExistsError.Sha1) {
			return false, nil
		}

		// If the files are not identical, then we can overwrite the file in two situations:
		// 1. One of the packages replaces the other.
		// 2. The packages are in the same origin.

		// If the existing file's package replaces the package we want to install, we don't need to write this file.
		pk, ok := a.installedFiles[header.Name]
		if !ok {
			return false, fmt.Errorf("found existing file we did not install (this should never happen): %s", header.Name)
		}

		for _, rep := range pk.Replaces {
			if pkg.Name == rep {
				return false, nil
			}
		}

		// Otherwise, we can only overwrite the file if it's in the same origin or if it replaces the existing package.
		_, isReplaced := replaceMap[pk.Name]
		if pk.Origin != pkg.Origin && !isReplaced {
			return false, FileConflictError{
				Path: header.Name,
				Origins: map[string]string{
					pk.Name:  pk.Origin,
					pkg.Name: pkg.Origin,
				},
			}
		}

		if err := a.writeOneFile(header, r, true); err != nil {
			return false, err
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

	// xattrs
	for k, v := range header.PAXRecords {
		if !strings.HasPrefix(k, xattrTarPAXRecordsPrefix) {
			continue
		}
		attrName := strings.TrimPrefix(k, xattrTarPAXRecordsPrefix)
		if err := a.fs.SetXattr(header.Name, attrName, []byte(v)); err != nil {
			return false, fmt.Errorf("error setting xattr %s on %s: %w", attrName, header.Name, err)
		}
	}
	return true, nil
}

// installAPKFiles install the files from the APK and return the list of installed files
// and their permissions. Returns a tar.Header because it is a convenient existing
// struct that has all of the fields we need.
func (a *APK) installAPKFiles(ctx context.Context, in io.Reader, pkg *Package) ([]tar.Header, error) {
	_, span := otel.Tracer("go-apk").Start(ctx, "installAPKFiles")
	defer span.End()

	var files []tar.Header
	tmpDir, err := os.MkdirTemp("", "apk-install")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// per https://git.alpinelinux.org/apk-tools/tree/src/extract_v2.c?id=337734941831dae9a6aa441e38611c43a5fd72c0#n120
	//  * APKv1.0 compatibility - first non-hidden file is
	//  * considered to start the data section of the file.
	//  * This does not make any sense if the file has v2.0
	//  * style .PKGINFO
	var startedDataSection bool
	tr := tar.NewReader(in)
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
			// xattrs
			for k, v := range header.PAXRecords {
				if !strings.HasPrefix(k, xattrTarPAXRecordsPrefix) {
					continue
				}
				attrName := strings.TrimPrefix(k, xattrTarPAXRecordsPrefix)
				if err := a.fs.SetXattr(header.Name, attrName, []byte(v)); err != nil {
					return nil, fmt.Errorf("error setting xattr %s on %s: %w", attrName, header.Name, err)
				}
			}

		case tar.TypeReg:
			installed, err := a.installRegularFile(header, tr, tmpDir, pkg)
			if err != nil {
				return nil, err
			}

			if installed {
				a.installedFiles[header.Name] = pkg

				if err := a.fs.Chtimes(header.Name, header.AccessTime, header.ModTime); err != nil {
					return nil, fmt.Errorf("chtimes for %s: %w", header.Name, err)
				}
			}

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

func checksumFromHeader(header *tar.Header) ([]byte, error) {
	pax := header.PAXRecords
	if pax == nil {
		return nil, nil
	}

	hexsum, ok := pax[paxRecordsChecksumKey]
	if !ok {
		return nil, nil
	}

	if strings.HasPrefix(hexsum, "Q1") {
		// This is nonstandard but something we did at one point, handle it.
		// In other contexts, this Q1 prefix means "this is sha1 not md5".
		b64 := strings.TrimPrefix(hexsum, "Q1")

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

// lazilyInstallAPKFiles avoids actually writing anything to disk, instead relying on a tarfs.FS
// to provide much cheaper access to the file data when we read it later.
//
// This is an optimizing fastpath for when a.fs is a specific implementation that supports it.
func (a *APK) lazilyInstallAPKFiles(ctx context.Context, wh WriteHeaderer, tf *tarfs.FS, pkg *Package) ([]tar.Header, error) {
	_, span := otel.Tracer("go-apk").Start(ctx, "lazilyInstallAPKFiles")
	defer span.End()

	entries := tf.Entries()
	files := make([]tar.Header, 0, len(entries))

	var startedDataSection bool
	for _, file := range entries {
		// per https://git.alpinelinux.org/apk-tools/tree/src/extract_v2.c?id=337734941831dae9a6aa441e38611c43a5fd72c0#n120
		//  * APKv1.0 compatibility - first non-hidden file is
		//  * considered to start the data section of the file.
		//  * This does not make any sense if the file has v2.0
		//  * style .PKGINFO
		if !startedDataSection && file.Header.Name[0] == '.' && !strings.Contains(file.Header.Name, "/") {
			continue
		}
		// whatever it is now, it is in the data section
		startedDataSection = true

		installed, err := wh.WriteHeader(file.Header, tf, pkg)
		if err != nil {
			return nil, err
		}

		if installed && file.Header.Typeflag == tar.TypeReg {
			a.installedFiles[file.Header.Name] = pkg
		}

		files = append(files, file.Header)
	}

	return files, nil
}
