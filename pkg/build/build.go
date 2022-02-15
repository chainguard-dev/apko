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
	bc := BuildContext{}

	log.Printf("building image '%s' from config file '%s'", imageRef, configFile)

	ic, err := LoadImageConfiguration(configFile)
	if err != nil {
		log.Fatalf("failed to load image configuration: %v", err)
	}
	bc.ImageConfiguration = ic

	wd, err := os.MkdirTemp("", "apko-*")
	if err != nil {
		log.Fatalf("failed to create working directory: %v", err)
	}
	bc.WorkDir = wd
	defer os.RemoveAll(bc.WorkDir)

	bc.Summarize()

	// initialize apk
	bc.InitApkDb()
	bc.InitApkKeyring()
	bc.InitApkRepositories()
	bc.InitApkWorld()

	// sync reality with desired apk world
	bc.FixateApkWorld()

        return nil
}
