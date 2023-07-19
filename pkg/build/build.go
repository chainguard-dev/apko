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

package build

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

import (
	"compress/gzip"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	apkfs "github.com/chainguard-dev/go-apk/pkg/fs"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/hashicorp/go-multierror"
	"go.opentelemetry.io/otel"
	"gopkg.in/yaml.v3"

	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/log"
	"chainguard.dev/apko/pkg/options"
	"chainguard.dev/apko/pkg/s6"
)

// Context contains all of the information necessary to build an
// OCI image. Includes the configurationfor the build,
// the path to the config file, the executor for root jails and
// architecture emulation, the s6 supervisor to add to the image,
// build options, and the `buildImplementation`, which handles the actual build.
type Context struct {
	// ImageConfiguration instructions to use for the build, normally from an apko.yaml file, but can be set directly.
	ImageConfiguration types.ImageConfiguration
	// ImageConfigFile path to the config file used, if any, to load the ImageConfiguration
	ImageConfigFile string
	s6              *s6.Context
	Assertions      []Assertion
	Options         options.Options
	fs              apkfs.FullFS
}

func (bc *Context) Summarize() {
	bc.Logger().Printf("build context:")
	bc.Options.Summarize(bc.Logger())
	bc.ImageConfiguration.Summarize(bc.Logger())
}

func (bc *Context) GetBuildDateEpoch() (time.Time, error) {
	if _, ok := os.LookupEnv("SOURCE_DATE_EPOCH"); ok {
		return bc.Options.SourceDateEpoch, nil
	}
	pl, err := bc.InstalledPackages()
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to determine installed packages: %w", err)
	}
	bde := bc.Options.SourceDateEpoch
	for _, p := range pl {
		if p.BuildTime.After(bde) {
			bde = p.BuildTime
		}
	}
	return bde, nil
}

func (bc *Context) BuildImage(ctx context.Context) error {
	if err := bc.buildImage(ctx); err != nil {
		logger := bc.Options.Logger()
		logger.Debugf("buildImage failed: %v", err)
		b, err2 := yaml.Marshal(bc.ImageConfiguration)
		if err2 != nil {
			logger.Debugf("failed to marshal image configuration: %v", err2)
		} else {
			logger.Debugf("image configuration:\n%s", string(b))
		}
		return err
	}
	return nil
}

func (bc *Context) Logger() log.Logger {
	return bc.Options.Logger()
}

// BuildLayer given the context set up, including
// build configuration and working directory,
// lays out all of the packages in the working directory,
// sets up the necessary user accounts and groups,
// and sets everything up in the directory. Then
// packages it all up into a standard OCI image layer
// tar.gz file.
func (bc *Context) BuildLayer(ctx context.Context) (string, v1.Layer, error) {
	ctx, span := otel.Tracer("apko").Start(ctx, "BuildLayer")
	defer span.End()

	bc.Summarize()

	// build image filesystem
	if err := bc.BuildImage(ctx); err != nil {
		return "", nil, err
	}

	return bc.ImageLayoutToLayer(ctx)
}

// ImageLayoutToLayer given an already built-out
// image in an fs from BuildImage(), create
// an OCI image layer tgz.
func (bc *Context) ImageLayoutToLayer(ctx context.Context) (string, v1.Layer, error) {
	ctx, span := otel.Tracer("apko").Start(ctx, "ImageLayoutToLayer")
	defer span.End()

	// run any assertions defined
	if err := bc.runAssertions(); err != nil {
		return "", nil, err
	}

	layerTarGZ, diffid, digest, size, err := bc.BuildTarball(ctx)
	// build layer tarball
	if err != nil {
		return "", nil, err
	}

	h := v1.Hash{
		Algorithm: "sha256",
		Hex:       hex.EncodeToString(digest.Sum(make([]byte, 0, digest.Size()))),
	}

	mt := v1types.OCILayer
	if bc.Options.UseDockerMediaTypes {
		mt = v1types.DockerLayer
	}

	l := &layer{
		filename: layerTarGZ,
		desc: &v1.Descriptor{
			Digest:    h,
			Size:      size,
			MediaType: mt,
		},
		diffid: &v1.Hash{
			Algorithm: "sha256",
			Hex:       hex.EncodeToString(diffid.Sum(make([]byte, 0, diffid.Size()))),
		},
	}

	return layerTarGZ, l, nil
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
	fs := apkfs.DirFS(workDir, apkfs.WithCreateDir())
	bc := Context{
		Options: options.Default,
		fs:      fs,
	}
	bc.Options.WorkDir = workDir

	for _, opt := range opts {
		if err := opt(&bc); err != nil {
			return nil, err
		}
	}

	// SOURCE_DATE_EPOCH will always overwrite the build flag
	if v, ok := os.LookupEnv("SOURCE_DATE_EPOCH"); ok && len(strings.TrimSpace(v)) != 0 {
		// The value MUST be an ASCII representation of an integer
		// with no fractional component, identical to the output
		// format of date +%s.
		sec, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			// If the value is malformed, the build process
			// SHOULD exit with a non-zero error code.
			return nil, fmt.Errorf("failed to parse SOURCE_DATE_EPOCH: %w", err)
		}

		bc.Options.SourceDateEpoch = time.Unix(sec, 0).UTC()
	}

	// if arch is missing default to the running program's arch
	zeroArch := types.Architecture("")
	if bc.Options.Arch == zeroArch {
		bc.Options.Arch = types.ParseArchitecture(runtime.GOARCH)
	}

	if bc.Options.WithVCS && bc.ImageConfiguration.VCSUrl == "" {
		bc.ImageConfiguration.ProbeVCSUrl(bc.ImageConfigFile, bc.Logger())
	}

	return &bc, nil
}

// Refresh initializes the build process by creating a new s6 context.
func (bc *Context) Refresh() error {
	bc.Options.TarballPath = ""

	bc.s6 = s6.New(bc.fs, bc.Logger())

	return nil
}

// layer implements v1.Layer from go-containerregistry to avoid re-computing
// digests and diffids.
type layer struct {
	filename string
	diffid   *v1.Hash
	desc     *v1.Descriptor
}

func (l *layer) DiffID() (v1.Hash, error) {
	return *l.diffid, nil
}

func (l *layer) Digest() (v1.Hash, error) {
	return l.desc.Digest, nil
}

func (l *layer) Compressed() (io.ReadCloser, error) {
	return os.Open(l.filename)
}

func (l *layer) Uncompressed() (io.ReadCloser, error) {
	rc, err := l.Compressed()
	if err != nil {
		return nil, err
	}

	// In practice, this won't be called, but this should work anyway.
	zr, err := gzip.NewReader(rc)
	if err != nil {
		return nil, err
	}
	return zr, nil
}

func (l *layer) Size() (int64, error) {
	return l.desc.Size, nil
}

func (l *layer) MediaType() (v1types.MediaType, error) {
	return l.desc.MediaType, nil
}
