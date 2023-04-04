// Copyright 2022, 2023 Chainguard, Inc.
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

//go:build unix
// +build unix

package build

import (
	"fmt"
	"path/filepath"

	"golang.org/x/sys/unix"

	apkfs "chainguard.dev/apko/pkg/apk/impl/fs"
)

func (di *defaultBuildImplementation) InstallCharDevices(fsys apkfs.FullFS) error {
	devices := []struct {
		path  string
		major uint32
		minor uint32
	}{
		{"/dev/zero", 1, 5},
		{"/dev/urandom", 1, 9},
		{"/dev/null", 1, 3},
		{"/dev/random", 1, 8},
		{"/dev/console", 5, 1},
	}
	for _, dev := range devices {
		if _, err := fsys.Stat(dev.path); err == nil {
			continue
		}
		dir := filepath.Dir(dev.path)
		if err := fsys.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("creating directory %s: %w", dir, err)
		}
		if err := fsys.Mknod(dev.path, unix.S_IFCHR, int(unix.Mkdev(dev.major, dev.minor))); err != nil {
			return fmt.Errorf("creating character device %s: %w", dev.path, err)
		}
	}
	return nil
}
