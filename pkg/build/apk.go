// Copyright 2022 Chainguard, Inc.
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

package build

import (
	"log"
	"os"
	"strings"

	"github.com/pkg/errors"
)

// Programmatic wrapper around apk-tools.  For now, this is done with os.Exec(),
// but this has been designed so that we can port it easily to use libapk-go once
// it is ready.

// Initialize the APK database for a given build context.  It is assumed that
// the build context itself is properly set up, and that `bc.WorkDir` is set
// to the path of a working directory.
func (bc *BuildContext) InitApkDB() error {
	log.Printf("initializing apk database")

	return Execute("apk", "add", "--initdb", "--root", bc.WorkDir)
}

// Installs the specified keys into the APK keyring inside the build context.
func (bc *BuildContext) InitApkKeyring() error {
	log.Printf("initializing apk keyring")

	err := os.MkdirAll(bc.WorkDir+"/etc/apk/keys", 0755)
	if err != nil {
		return errors.Wrap(err, "failed to make keys dir")
	}

	for _, element := range bc.ImageConfiguration.Contents.Keyring {
		log.Printf("installing key %v", element)

		data, err := os.ReadFile(element)
		if err != nil {
			return errors.Wrap(err, "failed to read apk key")
		}

		// #nosec G306 -- apk keyring must be publicly readable
		err = os.WriteFile(bc.WorkDir+"/"+element, data, 0644)
		if err != nil {
			return errors.Wrap(err, "failed to write apk key")
		}
	}

	return nil
}

// Generates a specified /etc/apk/repositories file in the build context.
func (bc *BuildContext) InitApkRepositories() error {
	log.Printf("initializing apk repositories")

	data := strings.Join(bc.ImageConfiguration.Contents.Repositories, "\n")

	// #nosec G306 -- apk repositories must be publicly readable
	err := os.WriteFile(bc.WorkDir+"/etc/apk/repositories", []byte(data), 0644)
	if err != nil {
		return errors.Wrap(err, "failed to write apk repositories list")
	}

	return nil
}

// Generates a specified /etc/apk/world file in the build context.
func (bc *BuildContext) InitApkWorld() error {
	log.Printf("initializing apk world")

	data := strings.Join(bc.ImageConfiguration.Contents.Packages, "\n")

	// #nosec G306 -- apk world must be publicly readable
	err := os.WriteFile(bc.WorkDir+"/etc/apk/world", []byte(data), 0644)
	if err != nil {
		return errors.Wrap(err, "failed to write apk world")
	}

	return nil
}

// Force apk's resolver to re-resolve the requested dependencies in /etc/apk/world.
func (bc *BuildContext) FixateApkWorld() error {
	log.Printf("synchronizing with desired apk world")

	return Execute("apk", "fix", "--root", bc.WorkDir, "--no-cache", "--update-cache")
}
