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
	WorkDir            string
	TarballPath        string
	UseProot           bool
	Tags               []string
	SourceDateEpoch    time.Time
	Assertions         []Assertion
	WantSBOM           bool
	SBOMPath           string
	SBOMFormats        []string
	ExtraKeyFiles      []string
	ExtraRepos         []string
	Arch               types.Architecture
	executor           *exec.Executor
	s6                 *s6.Context
	Log                *log.Logger
}

func (bc *Context) Summarize() {
	bc.Log.Printf("build context:")
	bc.Log.Printf("  working directory: %s", bc.WorkDir)
	bc.Log.Printf("  tarball path: %s", bc.TarballPath)
	bc.Log.Printf("  use proot: %t", bc.UseProot)
	bc.Log.Printf("  source date: %s", bc.SourceDateEpoch)
	bc.Log.Printf("  SBOM output path: %s", bc.SBOMPath)
	bc.Log.Printf("  arch: %v", bc.Arch.ToAPK())
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
		return "", fmt.Errorf("opening the build context tarball path failed: %w", err)
	}
	bc.TarballPath = outfile.Name()
	defer outfile.Close()

	tw, err := tarball.NewContext(tarball.WithSourceDateEpoch(bc.SourceDateEpoch))
	if err != nil {
		return "", fmt.Errorf("failed to construct tarball build context: %w", err)
	}

	if err := tw.WriteArchive(outfile, apkofs.DirFS(bc.WorkDir)); err != nil {
		return "", fmt.Errorf("failed to generate tarball for image: %w", err)
	}

	bc.Log.Printf("built image layer tarball as %s", outfile.Name())
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
		WorkDir: workDir,
		Log: log.New(log.Writer(), "apko", log.LstdFlags | log.Lmsgprefix),
	}

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

		bc.SourceDateEpoch = time.Unix(sec, 0)
	}

	// if arch is missing default to the running program's arch
	if bc.Arch == "" {
		bc.Arch = types.Architecture(runtime.GOARCH)
	}

	execOpts := []exec.Option{exec.WithProot(bc.UseProot)}
	if bc.UseProot && bc.Arch != types.Architecture(runtime.GOARCH) {
		execOpts = append(execOpts, exec.WithQemu(bc.Arch.ToAPK()))
	}

	executor, err := exec.New(bc.WorkDir, execOpts...)
	if err != nil {
		return nil, err
	}
	bc.executor = executor

	bc.s6 = s6.New(bc.WorkDir)

	bc.Log.SetPrefix(fmt.Sprintf("%s: ", bc.Arch.ToAPK()))

	return &bc, nil
}

// Option is an option for the build context.
type Option func(*Context) error

// WithConfig sets the image configuration for the build context.
// The image configuration is parsed from given config file.
func WithConfig(configFile string) Option {
	return func(bc *Context) error {
		bc.Log.Printf("loading config file: %s", configFile)

		var ic types.ImageConfiguration
		if err := ic.Load(configFile); err != nil {
			return fmt.Errorf("failed to load image configuration: %w", err)
		}

		bc.ImageConfiguration = ic
		return nil
	}
}

// WithProot enables proot for rootless image builds.
func WithProot(enable bool) Option {
	return func(bc *Context) error {
		bc.UseProot = enable
		return nil
	}
}

// WithTags sets the tags for the build context.
func WithTags(tags ...string) Option {
	return func(bc *Context) error {
		bc.Tags = tags
		return nil
	}
}

// WithTarball sets the output path of the layer tarball.
func WithTarball(path string) Option {
	return func(bc *Context) error {
		bc.TarballPath = path
		return nil
	}
}

// WithAssertions adds assertions to validate the result
// of this build context.
// Assertions are checked in parallel at the end of the
// build process.
func WithAssertions(a ...Assertion) Option {
	return func(bc *Context) error {
		bc.Assertions = append(bc.Assertions, a...)
		return nil
	}
}

// WithBuildDate sets the timestamps for the build context.
// The string is parsed according to RFC3339.
// An empty string is a special case and will default to
// the unix epoch.
func WithBuildDate(s string) Option {
	return func(bc *Context) error {
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

func WithSBOM(path string) Option {
	return func(bc *Context) error {
		bc.SBOMPath = path
		return nil
	}
}

func WithSBOMFormats(formats []string) Option {
	return func(bc *Context) error {
		bc.SBOMFormats = formats
		return nil
	}
}

func WithExtraKeys(keys []string) Option {
	return func(bc *Context) error {
		bc.ExtraKeyFiles = keys
		return nil
	}
}

func WithExtraRepos(repos []string) Option {
	return func(bc *Context) error {
		bc.ExtraRepos = repos
		return nil
	}
}

// WithImageConfiguration sets the ImageConfiguration object
// to use when building.
func WithImageConfiguration(ic types.ImageConfiguration) Option {
	return func(bc *Context) error {
		bc.ImageConfiguration = ic
		return nil
	}
}

// WithArch sets the architecture for the build context.
func WithArch(arch types.Architecture) Option {
	return func(bc *Context) error {
		bc.Arch = arch
		return nil
	}
}
