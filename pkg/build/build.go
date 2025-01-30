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

import (
	"compress/gzip"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"go.opentelemetry.io/otel"
	"gopkg.in/yaml.v3"

	"github.com/chainguard-dev/clog"

	"chainguard.dev/apko/pkg/apk/apk"
	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/baseimg"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/options"
	"chainguard.dev/apko/pkg/paths"
	"chainguard.dev/apko/pkg/s6"
)

// Context contains all of the information necessary to build an
// OCI image. Includes the configurationfor the build,
// the path to the config file, the executor for root jails and
// architecture emulation, the s6 supervisor to add to the image,
// build options, and the `buildImplementation`, which handles the actual build.
type Context struct {
	// ImageConfiguration instructions to use for the build, normally from an apko.yaml file, but can be set directly.
	ic types.ImageConfiguration
	o  options.Options

	s6      *s6.Context
	fs      apkfs.FullFS
	apk     *apk.APK
	baseimg *baseimg.BaseImage
}

func (bc *Context) Summarize(ctx context.Context) {
	bc.ic.Summarize(ctx)
}

func (bc *Context) BaseImage() v1.Image {
	if bc.baseimg != nil {
		return bc.baseimg.Image()
	}
	return empty.Image
}

func (bc *Context) GetBuildDateEpoch() (time.Time, error) {
	if _, ok := os.LookupEnv("SOURCE_DATE_EPOCH"); ok {
		return bc.o.SourceDateEpoch, nil
	}
	pl, err := bc.apk.GetInstalled()
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to determine installed packages: %w", err)
	}
	bde := bc.o.SourceDateEpoch
	for _, p := range pl {
		if p.BuildTime.After(bde) {
			bde = p.BuildTime
		}
	}
	return bde, nil
}

func (bc *Context) BuildImage(ctx context.Context) error {
	log := clog.FromContext(ctx)

	ctx, span := otel.Tracer("apko").Start(ctx, "BuildImage")
	defer span.End()

	if err := bc.buildImage(ctx); err != nil {
		log.Debugf("buildImage failed: %v", err)
		b, err2 := yaml.Marshal(bc.ic)
		if err2 != nil {
			log.Debugf("failed to marshal image configuration: %v", err2)
		} else {
			log.Debugf("image configuration:\n%s", string(b))
		}
		return err
	}
	return nil
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

	// build image filesystem
	if err := bc.BuildImage(ctx); err != nil {
		return "", nil, err
	}
	if err := bc.postBuildSetApk(ctx); err != nil {
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

	if err := bc.checkPaths(ctx); err != nil {
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

	l := &layer{
		filename: layerTarGZ,
		desc: &v1.Descriptor{
			Digest:    h,
			Size:      size,
			MediaType: v1types.OCILayer,
		},
		diffid: &v1.Hash{
			Algorithm: "sha256",
			Hex:       hex.EncodeToString(diffid.Sum(make([]byte, 0, diffid.Size()))),
		},
	}

	return layerTarGZ, l, nil
}

func (bc *Context) checkPaths(ctx context.Context) error {
	log := clog.FromContext(ctx)

	for _, p := range []string{
		"/etc/passwd",
		"/etc/group",
		"/etc/os-release",
	} {
		if _, err := bc.fs.Stat(p); errors.Is(err, os.ErrNotExist) {
			log.Warnf("%s is missing", p)
		} else if err != nil {
			return fmt.Errorf("checking %s file: %w", p, err)
		}
	}
	return nil
}

// NewOptions evaluates the build.Options in the same way as New().
func NewOptions(opts ...Option) (*options.Options, *types.ImageConfiguration, error) {
	bc := Context{
		o: options.Default,
	}

	for _, opt := range opts {
		if err := opt(&bc); err != nil {
			return nil, nil, err
		}
	}

	return &bc.o, &bc.ic, nil
}

// New creates a build context.
// The SOURCE_DATE_EPOCH env variable is supported and will
// overwrite the provided timestamp if present.
func New(ctx context.Context, fs apkfs.FullFS, opts ...Option) (*Context, error) {
	log := clog.FromContext(ctx)

	ctx, span := otel.Tracer("apko").Start(ctx, "New")
	defer span.End()

	bc := Context{
		o:  options.Default,
		fs: fs,
	}

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

		bc.o.SourceDateEpoch = time.Unix(sec, 0).UTC()
	}

	// if arch is missing default to the running program's arch
	zeroArch := types.Architecture("")
	if bc.o.Arch == zeroArch {
		bc.o.Arch = types.ParseArchitecture(runtime.GOARCH)
	}

	apkOpts := []apk.Option{
		apk.WithFS(bc.fs),
		apk.WithArch(bc.o.Arch.ToAPK()),
		apk.WithIgnoreMknodErrors(true),
		apk.WithIgnoreIndexSignatures(bc.o.IgnoreSignatures),
		apk.WithAuthenticator(bc.o.Auth),
		apk.WithTransport(bc.o.Transport),
	}
	// only try to pass the cache dir if one of the following is true:
	// - the user has explicitly set a cache dir
	// - the user's system-determined cachedir, as set by os.UserCacheDir(), can be found
	// if neither of these are true, then we don't want to pass a cache dir, because
	// go-apk will try to set it to os.UserCacheDir() which returns an error if $HOME
	// is not set.

	// note that this is not easy to do in a switch statement, because of the second
	// condition, if err := ...; err == nil {}
	if bc.o.CacheDir != "" {
		apkOpts = append(apkOpts, apk.WithCache(bc.o.CacheDir, bc.o.Offline, bc.o.SharedCache))
	} else if _, err := os.UserCacheDir(); err == nil {
		apkOpts = append(apkOpts, apk.WithCache(bc.o.CacheDir, bc.o.Offline, bc.o.SharedCache))
	} else {
		log.Warnf("cache disabled because cache dir was not set, and cannot determine system default: %v", err)
	}

	if bc.ic.Contents.BaseImage != nil {
		imgPath, err := paths.ResolvePath(bc.ic.Contents.BaseImage.Image, bc.o.IncludePaths)
		if err != nil {
			return nil, err
		}
		apkindexPath, err := paths.ResolvePath(bc.ic.Contents.BaseImage.APKIndex, bc.o.IncludePaths)
		if err != nil {
			return nil, err
		}
		baseImg, err := baseimg.New(imgPath, apkindexPath, bc.Arch(), bc.o.TempDir())
		if err != nil {
			return nil, err
		}
		bc.baseimg = baseImg
		// Apko checks signatures of all indexes by default. For the base image apk index we don't
		// have the signature. On the other hand we still want to check signatures of the remaining
		// indexes. This way we disable signature checks only for the base image apk index.
		apkOpts = append(apkOpts, apk.WithNoSignatureIndexes(bc.baseimg.APKIndexPath()))
	}

	apkImpl, err := apk.New(apkOpts...)
	if err != nil {
		return nil, err
	}

	bc.apk = apkImpl

	log.Debugf("doing pre-flight checks")
	if err := bc.ic.Validate(); err != nil {
		return nil, fmt.Errorf("failed to validate configuration: %w", err)
	}

	if err := bc.initializeApk(ctx); err != nil {
		return nil, fmt.Errorf("initializing apk: %w", err)
	}

	bc.s6 = s6.New(bc.fs)

	return &bc, nil
}

type notAFile struct {
	rc *os.File
}

func (f *notAFile) Read(p []byte) (int, error) {
	return f.rc.Read(p)
}

func (f *notAFile) Close() error {
	return f.rc.Close()
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
	f, err := os.Open(l.filename)
	if err != nil {
		return nil, err
	}

	// There is a bug in how go uses sendfile on macos, so we need to make this not a file.
	// See https://github.com/golang/go/issues/70000
	return &notAFile{f}, nil
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

// Here be dragons:
// There was previously a pattern of accessing build.New().Options for convenience.
// This unfortunately led to a lot of mutation of build.Context.Options for convenience.
// This led to impossible (for the humble author of this comment) to follow logic.
// Ideally, these methods just go away over time, but for now this makes the diff simple
// (and lets us track exactly what kind of Law of Demeter violations we rely on).

func (bc *Context) ImageConfiguration() types.ImageConfiguration {
	return bc.ic
}

func (bc *Context) TarballPath() string {
	return bc.o.TarballPath
}

func (bc *Context) Arch() types.Architecture {
	return bc.o.Arch
}

func (bc *Context) WantSBOM() bool {
	return len(bc.o.SBOMFormats) != 0
}
