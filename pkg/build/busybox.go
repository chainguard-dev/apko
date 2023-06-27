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

// This depends on knowing the correct links for each version.
// These are kept in a map in busybox_versions.go, which is generated.
// However, those are just a fallback. Beginning with alpine busybox 1.36.0-r8
// and wolfi 1.36.0-r3, it includes a manifest of links in /etc/busybox-paths.d/<package-name>
//
// To regenerate, run the following from the repository root:
//
// go generate -tags busybox_versions ./pkg/build/busybox_gen.go

package build

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	apkfs "github.com/chainguard-dev/go-apk/pkg/fs"

	chainguardAPK "chainguard.dev/apko/pkg/apk"
	"chainguard.dev/apko/pkg/options"
)

const (
	busybox      = "/bin/busybox"
	busyboxPaths = "/etc/busybox-paths.d"
)

// for reference, the list of versions can be updated from curl -L https://distfiles.alpinelinux.org/distfiles/edge/ | grep busybox
// we do everything higher than the version below

var basicSemverRegex = regexp.MustCompile(`^v?((\d+)\.(\d+)\.(\d+))(?:-(\w+))?$`)

var busyboxLinks map[string][]string

// /bin/busybox --list-full | sort | sed 's|^|/|g'
// note that it changes based on version of busybox,
// so this should be updated to match busybox version.

func (di *buildImplementation) InstallBusyboxLinks(fsys apkfs.FullFS, o *options.Options) error {
	// does busybox exist? if not, do not bother with symlinks
	if _, err := fsys.Stat(busybox); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	// get the busybox version
	apk, err := chainguardAPK.NewWithOptions(fsys, *o)
	if err != nil {
		return err
	}
	installed, err := apk.GetInstalled()
	if err != nil {
		return err
	}
	var (
		installedVersion string
		pkgName          string
	)
	for _, pkg := range installed {
		if pkg.Name == "busybox" {
			// get the version
			installedVersion = pkg.Version
			pkgName = pkg.Name
			break
		}
		// Other packages might "provide" busybox
		for _, prov := range pkg.Provides {
			if strings.Contains(prov, "busybox") {
				installedVersion = pkg.Version
				pkgName = pkg.Name
				break
			}
		}
	}
	if installedVersion == "" {
		return fmt.Errorf("busybox package not installed")
	}

	var links []string
	// first look in /etc/busybox-paths.d/<package>
	// if that does not exist, use the fallback map
	pathsFilename := filepath.Join(busyboxPaths, pkgName)
	if b, err := fsys.ReadFile(pathsFilename); err == nil {
		links = strings.Split(string(b), "\n")
	} else {
		var ok bool
		// convert to a basic semver
		matches := basicSemverRegex.FindAllStringSubmatch(installedVersion, -1)
		if len(matches) != 1 || len(matches[0]) < 4 {
			return fmt.Errorf("invalid busybox version: %s", installedVersion)
		}
		installedVersion = matches[0][1]
		links, ok = busyboxLinks[installedVersion]
		if !ok {
			links = busyboxLinks["default"]
		}
	}

	for _, link := range links {
		if link == busybox || link == "" {
			continue
		}
		dir := filepath.Dir(link)
		if err := fsys.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("creating directory %s: %w", dir, err)
		}
		if err := fsys.Symlink(busybox, link); err != nil {
			// sometimes the list generates links twice, so do not error on that
			if errors.Is(err, os.ErrExist) {
				// ignore if it already is a symlink, in line with what `busybox --install -s`` does
				if _, err := fsys.Readlink(link); err == nil {
					continue
				}
				// ignore if it already is a regular file
				if err != nil {
					fi, err := fsys.Stat(link)
					if err == nil && fi.Mode().IsRegular() {
						continue
					}
				}
			}
			return fmt.Errorf("creating busybox link %s: %w", link, err)
		}
	}
	return nil
}
