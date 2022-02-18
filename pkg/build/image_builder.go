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

	"github.com/pkg/errors"
)

// Builds the image in BuildContext.WorkDir.
func (bc *BuildContext) BuildImage() error {
	log.Printf("doing pre-flight checks")
	err := bc.ImageConfiguration.Validate()
	if err != nil {
		return errors.Wrap(err, "failed to validate configuration")
	}

	log.Printf("building image fileystem in %s", bc.WorkDir)

	// initialize apk
	err = bc.InitApkDb()
	if err != nil {
		return errors.Wrap(err, "failed to initialize apk database")
	}

	err = bc.InitApkKeyring()
	if err != nil {
		return errors.Wrap(err, "failed to initialize apk keyring")
	}

	err = bc.InitApkRepositories()
	if err != nil {
		return errors.Wrap(err, "failed to initialize apk repositories")
	}

	err = bc.InitApkWorld()
	if err != nil {
		return errors.Wrap(err, "failed to initialize apk world")
	}

	// sync reality with desired apk world
	err = bc.FixateApkWorld()
	if err != nil {
		return errors.Wrap(err, "failed to fixate apk world")
	}

	// write service supervision tree
	err = bc.WriteSupervisionTree()
	if err != nil {
		return errors.Wrap(err, "failed to write supervision tree")
	}

	log.Printf("finished building filesystem in %s", bc.WorkDir)
	return nil
}
