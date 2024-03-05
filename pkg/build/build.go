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
	"archive/tar"
	"bytes"
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

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/go-apk/pkg/apk"
	apkfs "github.com/chainguard-dev/go-apk/pkg/fs"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"go.opentelemetry.io/otel"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"

	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/options"
	"chainguard.dev/apko/pkg/s6"
)

type BaseImage struct {
	img      v1.Image
	apkIndex []byte
	tmpDir   string
	arch     types.Architecture
}

func extractFile(image v1.Image, filename string) ([]byte, error) {
	fs := mutate.Extract(image)
	defer fs.Close()
	reader := tar.NewReader(fs)
	for header, err := reader.Next(); err == nil; header, err = reader.Next() {
		if header.Name == filename {
			b, err := io.ReadAll(reader)
			return b, err
		}
	}
	return nil, fmt.Errorf("failed to get File")
}

func getImageForArch(imgPath string, arch types.Architecture) (v1.Image, error) {
	index, err := layout.ImageIndexFromPath(imgPath)
	if err != nil {
		return nil, err
	}
	indexManifest, err := index.IndexManifest()
	if err != nil {
		return nil, err
	}

	for _, m := range indexManifest.Manifests {
		if m.Platform.Architecture == arch.ToOCIPlatform().Architecture {
			img, err := index.Image(m.Digest)
			if err != nil {
				return nil, err
			}
			return img, nil
		}
	}
	return nil, fmt.Errorf("image for arch not found")
}

func NewBaseImage(imgPath string, arch types.Architecture, tmpDir string) (*BaseImage, error) {
	img, err := getImageForArch(imgPath, arch)
	if err != nil {
		return nil, err
	}
	contents, err := extractFile(img, "lib/apk/db/installed")
	if err != nil {
		return nil, err
	}
	return &BaseImage{
			img:      img,
			apkIndex: contents,
			tmpDir:   tmpDir,
			arch:     arch,
		},
		nil
}

func (baseImg *BaseImage) Packages() ([]string, error) {
	reader := bytes.NewReader(baseImg.apkIndex)
	apkPkgs, err := apk.ParsePackageIndex(reader)
	if err != nil {
		return nil, err
	}
	var packages []string
	for _, pkg := range apkPkgs {
		packages = append(packages, fmt.Sprintf("%s=%s", pkg.Name, pkg.Version))
	}
	return packages, nil
}

func (baseImg *BaseImage) APKPackages() ([]*apk.Package, error) {
	reader := bytes.NewReader(baseImg.apkIndex)
	return apk.ParsePackageIndex(reader)
}

func (baseImg *BaseImage) APKIndexPath() string {
	return baseImg.tmpDir + "/base_image_apkindex"
}

func (baseImg *BaseImage) CreateAPKIndexArchive() error {
	baseDir := baseImg.APKIndexPath()
	archDir := baseDir + "/" + baseImg.arch.ToAPK()
	if err := os.Mkdir(baseDir, 0777); err != nil {
		return err
	}
	if err := os.Mkdir(archDir, 0777); err != nil {
		return err
	}
	TarFile, err := os.OpenFile(archDir+"/APKINDEX.tar.gz", os.O_CREATE|os.O_WRONLY, 0777)
	if err != nil {
		return err
	}
	defer TarFile.Close()
	gzipwriter := gzip.NewWriter(TarFile)
	defer gzipwriter.Close()
	tarWriter := tar.NewWriter(gzipwriter)
	defer tarWriter.Close()
	header := tar.Header{Name: "APKINDEX", Size: int64(len(baseImg.apkIndex)), Mode: 0777}
	if err := tarWriter.WriteHeader(&header); err != nil {
		return err
	}
	if _, err := tarWriter.Write(baseImg.apkIndex); err != nil {
		return err
	}
	return nil
}

// Context contains all of the information necessary to build an
// OCI image. Includes the configurationfor the build,
// the path to the config file, the executor for root jails and
// architecture emulation, the s6 supervisor to add to the image,
// build options, and the `buildImplementation`, which handles the actual build.
type Context struct {
	// ImageConfiguration instructions to use for the build, normally from an apko.yaml file, but can be set directly.
	ic types.ImageConfiguration
	o  options.Options

	s6         *s6.Context
	assertions []Assertion
	fs         apkfs.FullFS
	apk        *apk.APK
	baseimg    *BaseImage
}

func (bc *Context) Summarize(ctx context.Context) {
	bc.ic.Summarize(ctx)
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

func (bc *Context) runAssertions() error {
	errs := make([]error, len(bc.assertions))

	var eg errgroup.Group
	for i, a := range bc.assertions {
		i, a := i, a
		eg.Go(func() error {
			errs[i] = a(bc)

			// We don't want to fail early.
			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return err
	}

	return errors.Join(errs...)
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
		apkOpts = append(apkOpts, apk.WithCache(bc.o.CacheDir, bc.o.Offline))
	} else if _, err := os.UserCacheDir(); err == nil {
		apkOpts = append(apkOpts, apk.WithCache(bc.o.CacheDir, bc.o.Offline))
	} else {
		log.Warnf("cache disabled because cache dir was not set, and cannot determine system default: %v", err)
	}

	if bc.ic.Contents.BaseImage != "" {
		baseImg, err := NewBaseImage(bc.ic.Contents.BaseImage, bc.Arch(), bc.o.TempDir())
		if err != nil {
			return nil, err
		}
		bc.baseimg = baseImg
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
