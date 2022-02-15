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
	"context"
	"log"
	"os"
)

type BuildContext struct {
	ImageConfiguration	ImageConfiguration
	WorkDir			string
}

func (bc *BuildContext) Summarize() {
	log.Printf("build context:")
	log.Printf("  image configuration: %v", bc.ImageConfiguration)
	log.Printf("  working directory: %v", bc.WorkDir)
}

func BuildCmd(ctx context.Context, configFile string, imageRef string) error {
	log.Printf("building image '%s' from config file '%s'", imageRef, configFile)

	ic, err := LoadImageConfiguration(configFile)
	if err != nil {
		log.Fatalf("failed to load image configuration: %v", err)
	}

	wd, err := os.MkdirTemp("", "apko-*")
	if err != nil {
		log.Fatalf("failed to create working directory: %v", err)
	}
	defer os.RemoveAll(wd)

	bc := BuildContext{
		ImageConfiguration: ic,
		WorkDir: wd,
	}
	bc.Summarize()

	// initialize apk
	err = bc.InitApkDb()
	if err != nil {
		log.Fatalf("failed to initialize apk database: %v", err)
	}

	err = bc.InitApkKeyring()
	if err != nil {
		log.Fatalf("failed to initialize apk keyring: %v", err)
	}

	err = bc.InitApkRepositories()
	if err != nil {
		log.Fatalf("failed to initialize apk repositories: %v", err)
	}

	err = bc.InitApkWorld()
	if err != nil {
		log.Fatalf("failed to initialize apk world: %v", err)
	}

	// sync reality with desired apk world
	err = bc.FixateApkWorld()
	if err != nil {
		log.Fatalf("failed to fixate apk world: %v", err)
	}

        return nil
}
