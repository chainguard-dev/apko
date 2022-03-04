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
	"strconv"
	"time"

	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/tarball"

	"github.com/pkg/errors"
)

type Context struct {
	ImageConfiguration types.ImageConfiguration
	WorkDir            string
	TarballPath        string
	UseProot           bool
	Tags               []string
	SourceDateEpoch    time.Time
}

func (bc *Context) Summarize() {
	log.Printf("build context:")
	log.Printf("  working directory: %s", bc.WorkDir)
	log.Printf("  tarball path: %s", bc.TarballPath)
	log.Printf("  use proot: %t", bc.UseProot)
	bc.ImageConfiguration.Summarize()
}

func (bc *Context) BuildTarball() (string, error) {
	var outfile *os.File
	var err error

	if bc.TarballPath != "" {
		outfile, err = os.Create(bc.TarballPath)
	} else {
		outfile, err = os.CreateTemp("", "apko-*.tar.gz")
	}
	if err != nil {
		return "", errors.Wrap(err, "opening the build context tarball path failed")
	}
	defer outfile.Close()

	err = tarball.WriteArchive(bc.WorkDir, outfile, bc.SourceDateEpoch)
	if err != nil {
		return "", errors.Wrap(err, "failed to generate tarball for image")
	}

	log.Printf("built image layer tarball as %s", outfile.Name())
	return outfile.Name(), nil
}

func (bc *Context) BuildLayer() (string, error) {
	bc.Summarize()

	// build image filesystem
	err := bc.BuildImage()
	if err != nil {
		return "", err
	}

	// build layer tarball
	layerTarGZ, err := bc.BuildTarball()
	if err != nil {
		return "", err
	}

	return layerTarGZ, nil
}

type Option func(*Context) error

func WithConfig(configFile string) Option {
	return func(bc *Context) error {
		log.Printf("loading config file: %s", configFile)

		var ic types.ImageConfiguration
		if err := ic.Load(configFile); err != nil {
			return errors.Wrap(err, "failed to load image configuration")
		}

		bc.ImageConfiguration = ic
		return nil
	}
}

func WithProot(enable bool) Option {
	return func(bc *Context) error {
		bc.UseProot = enable
		return nil
	}
}

func WithTags(tags ...string) Option {
	return func(bc *Context) error {
		bc.Tags = tags
		return nil
	}
}

func WithTarball(path string) Option {
	return func(bc *Context) error {
		bc.TarballPath = path
		return nil
	}
}

func WithBuildDate(s string) Option {
	return func(bc *Context) error {
		// SOURCE_DATE_EPOCH takes priority
		if v, ok := os.LookupEnv("SOURCE_DATE_EPOCH"); ok {
			// The value MUST be an ASCII representation of an integer
			// with no fractional component, identical to the output
			// format of date +%s.
			sec, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				// If the value is malformed, the build process
				// SHOULD exit with a non-zero error code.
				return err
			}

			bc.SourceDateEpoch = time.Unix(sec, 0)
			return nil
		}

		// default to 0 for reproducibility
		if s == "" {
			bc.SourceDateEpoch = time.Unix(0, 0)
			return nil
		}

		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return err
		}

		bc.SourceDateEpoch = t
		return nil
	}
}
