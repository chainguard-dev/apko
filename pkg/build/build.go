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

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/sirupsen/logrus"

	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/exec"
	"chainguard.dev/apko/pkg/options"
	"chainguard.dev/apko/pkg/s6"
)

type Context struct {
	impl               buildImplementation
	ImageConfiguration types.ImageConfiguration
	executor           *exec.Executor
	s6                 *s6.Context
	Assertions         []Assertion
	Options            options.Options
}

func (bc *Context) Summarize() {
	bc.Options.Log.Printf("build context:")
	bc.Options.Summarize()
	bc.ImageConfiguration.Summarize(bc.Options.Log)
}

func (bc *Context) BuildTarball() (string, error) {
	return bc.impl.BuildTarball(&bc.Options)
}

func (bc *Context) GenerateSBOM() error {
	return bc.impl.GenerateSBOM(&bc.Options)
}

func (bc *Context) BuildImage() error {
	// TODO(puerco): Point to final interface (see comment on buildImage fn)
	return buildImage(bc.impl, &bc.Options, &bc.ImageConfiguration, bc.executor, bc.s6)
}

func (bc *Context) Logger() *logrus.Entry {
	zeroArch := types.Architecture{}
	if bc.Options.Arch != zeroArch {
		return bc.Options.Log.WithFields(logrus.Fields{
			"arch": bc.Options.Arch.ToAPK(),
		})
	}

	return logrus.NewEntry(bc.Options.Log)
}

func (bc *Context) BuildLayer() (string, error) {
	bc.Summarize()

	// build image filesystem
	if err := bc.BuildImage(); err != nil {
		return "", err
	}

	// run any assertions defined
	if err := bc.runAssertions(); err != nil {
		return "", err
	}

	// build layer tarball
	layerTarGZ, err := bc.BuildTarball()
	if err != nil {
		return "", err
	}

	// generate SBOM
	if err := bc.GenerateSBOM(); err != nil {
		return "", fmt.Errorf("generating SBOMs: %w", err)
	}

	return layerTarGZ, nil
}

func (bc *Context) runAssertions() error {
	var eg multierror.Group

	for _, a := range bc.Assertions {
		a := a
		eg.Go(func() error { return a(bc) })
	}

	return eg.Wait().ErrorOrNil()
}

// New creates a build context.
// The SOURCE_DATE_EPOCH env variable is supported and will
// overwrite the provided timestamp if present.
func New(workDir string, opts ...Option) (*Context, error) {
	bc := Context{
		Options: options.Default,
		impl:    &defaultBuildImplementation{},
	}
	bc.Options.WorkDir = workDir

	for _, opt := range opts {
		if err := opt(&bc); err != nil {
			return nil, err
		}
	}

	// SOURCE_DATE_EPOCH will always overwrite the build flag
	if v, ok := os.LookupEnv("SOURCE_DATE_EPOCH"); ok {
		// The value MUST be an ASCII representation of an integer
		// with no fractional component, identical to the output
		// format of date +%s.
		sec, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			// If the value is malformed, the build process
			// SHOULD exit with a non-zero error code.
			return nil, fmt.Errorf("failed to parse SOURCE_DATE_EPOCH: %w", err)
		}

		bc.Options.SourceDateEpoch = time.Unix(sec, 0)
	}

	// if arch is missing default to the running program's arch
	zeroArch := types.Architecture{}
	if bc.Options.Arch == zeroArch {
		bc.Options.Arch = types.ParseArchitecture(runtime.GOARCH)
	}

	return &bc, nil
}

func (bc *Context) Refresh() error {
	s6, executor, err := bc.impl.Refresh(&bc.Options)
	if err != nil {
		return err
	}

	bc.executor = executor
	bc.s6 = s6

	return nil
}

func (bc *Context) SetImplementation(i buildImplementation) {
	bc.impl = i
}
