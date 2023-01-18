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

package apk

import (
	"archive/tar"
	"time"

	apkimpl "chainguard.dev/apko/pkg/apk/impl"
)

//counterfeiter:generate . apkImplementation

type apkImplementation interface {
	// InitDB initializes the APK database and all directories.
	InitDB(versions ...string) error
	// InitKeyring initializes the keyring with the given keyfiles. The first argument, keyfiles, is a list of
	// keyfile locations. If present, they override the default keyfiles. The second argument, extraKeyfiles, is a list
	// of files to append to the existing ones.
	// Can provide file locations or URLs.
	InitKeyring(keyfiles, extraKeyfiles []string) error
	// SetWorld set the list of packages in the world file. Replaces any existing ones.
	SetWorld(packages []string) error
	// GetWorld get the list of packages in the world file.
	GetWorld() ([]string, error)
	// FixateWorld use the world file to set the state of the system, including any dependencies.
	FixateWorld(cache, updateCache, executeScripts bool, sourceDateEpoch *time.Time) error
	// SetRepositories sets the repositories to use. Replaces any existing ones.
	SetRepositories(repos []string) error
	// GetRepositories gets the list of repositories in use.
	GetRepositories() ([]string, error)
	// GetInstalled gets the list of installed packages.
	GetInstalled() ([]*apkimpl.InstalledPackage, error)
	// ListInitFiles lists the directories and files that are installed via InitDB
	ListInitFiles() []tar.Header
}
