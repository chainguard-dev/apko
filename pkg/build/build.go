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

	"chainguard.dev/apko/pkg/tarball"
	"github.com/pkg/errors"
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
		return errors.Wrap(err, "failed to load image configuration")
	}

	wd, err := os.MkdirTemp("", "apko-*")
	if err != nil {
		return errors.Wrap(err, "failed to create working directory")
	}
	defer os.RemoveAll(wd)

	bc := BuildContext{
		ImageConfiguration: ic,
		WorkDir: wd,
	}
	bc.Summarize()

	// build image filesystem
	bc.BuildImage()

	// build layer tarball
	outfile, err := os.CreateTemp("", "apko-*.tar.gz")
	if err != nil {
		return errors.Wrap(err, "opening a temporary file failed")
	}
	defer outfile.Close()

	err = tarball.WriteArchive(bc.WorkDir, outfile)
	if err != nil {
		return errors.Wrap(err, "failed to generate tarball for image")
	}
//	defer os.Remove(outfile.Name())

	log.Printf("built image layer tarball as %s", outfile.Name())

        return nil
}
