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

	chainguardAPK "chainguard.dev/apko/pkg/apk"
	apkfs "chainguard.dev/apko/pkg/apk/impl/fs"
	"chainguard.dev/apko/pkg/options"
)

// for reference, the list of versions can be updated from curl -L https://distfiles.alpinelinux.org/distfiles/edge/ | grep busybox
// we do everything higher than the version below

var basicSemverRegex = regexp.MustCompile(`^v?((\d+)\.(\d+)\.(\d+))(?:-(\w+))?$`)

var busyboxLinks map[string][]string

// /bin/busybox --list-full | sort | sed 's|^|/|g'
// note that it changes based on version of busybox,
// so this should be updated to match busybox version.

func (di *defaultBuildImplementation) InstallBusyboxLinks(fsys apkfs.FullFS, o *options.Options) error {
	// does busybox exist? if not, do not bother with symlinks
	if _, err := fsys.Stat("/bin/busybox"); err != nil {
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
	var installedVersion string
	for _, pkg := range installed {
		if pkg.Name == "busybox" {
			// get the version
			installedVersion = pkg.Version
			break
		}
		// Other packages might "provide" busybox
		for _, prov := range pkg.Provides {
			if strings.Contains(prov, "busybox") {
				installedVersion = pkg.Version
				break
			}
		}
	}
	if installedVersion == "" {
		return fmt.Errorf("busybox package not installed")
	}
	// convert to a basic semver
	matches := basicSemverRegex.FindAllStringSubmatch(installedVersion, -1)
	if len(matches) != 1 || len(matches[0]) < 4 {
		return fmt.Errorf("invalid busybox version: %s", installedVersion)
	}
	installedVersion = matches[0][1]
	links, ok := busyboxLinks[installedVersion]
	if !ok {
		links = busyboxLinks["default"]
	}

	for _, link := range links {
		dir := filepath.Dir(link)
		if err := fsys.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("creating directory %s: %w", dir, err)
		}
		if err := fsys.Symlink("/bin/busybox", link); err != nil {
			return fmt.Errorf("creating busybox link %s: %w", link, err)
		}
	}
	return nil
}
