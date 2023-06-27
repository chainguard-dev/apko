// Copyright 2023 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package build

import (
	"debug/elf"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	apkfs "github.com/chainguard-dev/go-apk/pkg/fs"
)

// original alpine ldconfig available at https://git.alpinelinux.org/aports/tree/main/musl/ldconfig

func ldconfig(vfs apkfs.OpenReaderAtFS, libdirs ...string) (map[string]string, error) {
	links := make(map[string]string)
	for _, libdir := range libdirs {
		entries, err := fs.ReadDir(vfs, libdir)
		if err != nil {
			return nil, fmt.Errorf("unable to read directory %s: %w", libdir, err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			absPath := filepath.Join(libdir, entry.Name())
			soname, err := getSoname(vfs, absPath)
			if err != nil {
				return nil, fmt.Errorf("unable to get soname for %s: %w", absPath, err)
			}
			if soname == "" {
				continue
			}
			target := entry.Name()
			link := filepath.Join(libdir, soname)
			// ignore if it already is in /lib or /usr/lib or /usr/local/lib
			if libdir == "/lib" || libdir == "/usr/lib" || libdir == "/usr/local/lib" || strings.HasPrefix(libdir, "/lib/") || strings.HasPrefix(libdir, "/usr/lib/") || strings.HasPrefix(libdir, "/usr/local/lib/") {
				continue
			}
			// ignore it if it already exists and is not a symlink
			f, err := vfs.Open(link)
			if err != nil {
				if !os.IsNotExist(err) {
					return nil, fmt.Errorf("unable to open link file %s: %w", link, err)
				}
				// does not exist, so add it
				links[link] = target
				continue
			}
			fi, err := f.Stat()
			if err != nil {
				f.Close()
				return nil, fmt.Errorf("unable to stat link file %s: %w", link, err)
			}
			if fi.Mode()&os.ModeSymlink != os.ModeSymlink {
				// it already exists but is not a symlink, do nothing
				f.Close()
				continue
			}
			// it exists and is a symlink, just add it to the override list
			links[link] = target
			f.Close()
		}
	}
	return links, nil
}

func getSoname(vfs apkfs.OpenReaderAtFS, path string) (string, error) {
	file, err := vfs.OpenReaderAt(path)
	if err != nil {
		return "", fmt.Errorf("unable to open file %s: %w", path, err)
	}
	defer file.Close()
	elfFile, err := elf.NewFile(file)
	if err != nil {
		// not an elf file, ignore
		return "", nil
	}
	defer elfFile.Close()
	dynStrings, err := elfFile.DynString(elf.DT_SONAME)
	if err != nil {
		return "", fmt.Errorf("unable to read elf headers %s: %w", path, err)
	}
	if len(dynStrings) < 1 {
		return "", nil
	}
	return dynStrings[0], nil
}

func (di *buildImplementation) InstallLdconfigLinks(fsys apkfs.FullFS) error {
	linksMap, err := ldconfig(fsys, "/lib")
	if err != nil {
		return err
	}
	for link, target := range linksMap {
		dir := filepath.Dir(link)
		if err := fsys.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("creating directory %s: %w", dir, err)
		}
		if err := fsys.Symlink(target, link); err != nil {
			return fmt.Errorf("creating link %s -> %s: %w", link, target, err)
		}
	}
	return nil
}
