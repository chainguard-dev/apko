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
	"fmt"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-multierror"

	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/exec"
	apkofs "chainguard.dev/apko/pkg/fs"
	"chainguard.dev/apko/pkg/s6"
	"chainguard.dev/apko/pkg/tarball"
)

type Context struct {
	ImageConfiguration types.ImageConfiguration
	executor           *exec.Executor
	s6                 *s6.Context
	Assertions         []Assertion
	Options            Options
}

type Options struct {
	WantSBOM        bool
	UseProot        bool
	WorkDir         string
	TarballPath     string
	Tags            []string
	SourceDateEpoch time.Time
	SBOMPath        string
	SBOMFormats     []string
	ExtraKeyFiles   []string
	ExtraRepos      []string
	Arch            types.Architecture
	Log             *log.Logger
}

var DefaultOptions Options

func (bc *Context) Summarize() {
	bc.Options.Log.Printf("build context:")
	bc.Options.Log.Printf("  working directory: %s", bc.Options.WorkDir)
	bc.Options.Log.Printf("  tarball path: %s", bc.Options.TarballPath)
	bc.Options.Log.Printf("  use proot: %t", bc.Options.UseProot)
	bc.Options.Log.Printf("  source date: %s", bc.Options.SourceDateEpoch)
	bc.Options.Log.Printf("  SBOM output path: %s", bc.Options.SBOMPath)
	bc.Options.Log.Printf("  arch: %v", bc.Options.Arch.ToAPK())
	bc.ImageConfiguration.Summarize(bc.Options.Log)
}

func (bc *Context) BuildTarball() (string, error) {
	var outfile *os.File
	var err error

	if bc.Options.TarballPath != "" {
		outfile, err = os.Create(bc.Options.TarballPath)
	} else {
		outfile, err = os.CreateTemp("", "apko-*.tar.gz")
	}
	if err != nil {
		return "", fmt.Errorf("opening the build context tarball path failed: %w", err)
	}
	bc.Options.TarballPath = outfile.Name()
	defer outfile.Close()

	tw, err := tarball.NewContext(tarball.WithSourceDateEpoch(bc.Options.SourceDateEpoch))
	if err != nil {
		return "", fmt.Errorf("failed to construct tarball build context: %w", err)
	}

	if err := tw.WriteArchive(outfile, apkofs.DirFS(bc.Options.WorkDir)); err != nil {
		return "", fmt.Errorf("failed to generate tarball for image: %w", err)
	}

	bc.Options.Log.Printf("built image layer tarball as %s", outfile.Name())
	return outfile.Name(), nil
}

func (bc *Context) BuildLayer() (string, error) {
	bc.Summarize()

	// build image filesystem
	if err := bc.BuildImage(); err != nil {
		return "", err
	}

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
		Options: DefaultOptions,
	}
	bc.Options.WorkDir = workDir
	bc.Options.Log = log.New(log.Writer(), "apko (early): ", log.LstdFlags|log.Lmsgprefix)

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
	bc.UpdatePrefix()

	if strings.HasPrefix(bc.Options.TarballPath, "/tmp/apko") {
		bc.Options.TarballPath = ""
	}

	hostArch := types.ParseArchitecture(runtime.GOARCH)

	execOpts := []exec.Option{exec.WithProot(bc.Options.UseProot)}
	if bc.Options.UseProot && !bc.Options.Arch.Compatible(hostArch) {
		bc.Options.Log.Printf("%q requires QEMU (not compatible with %q)", bc.Options.Arch, hostArch)
		execOpts = append(execOpts, exec.WithQemu(bc.Options.Arch.ToQEmu()))
	}

	executor, err := exec.New(bc.Options.WorkDir, bc.Options.Log, execOpts...)
	if err != nil {
		return err
	}
	bc.executor = executor

	bc.s6 = s6.New(bc.Options.WorkDir, bc.Options.Log)

	return nil
}

func (bc *Context) UpdatePrefix() {
	bc.Options.Log = log.New(log.Writer(), fmt.Sprintf("apko (%s): ", bc.Options.Arch.ToAPK()), log.LstdFlags|log.Lmsgprefix)
}
