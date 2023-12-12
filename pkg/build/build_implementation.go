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
	"bufio"
	"chainguard.dev/apko/pkg/lock"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"chainguard.dev/apko/pkg/options"

	gzip "github.com/klauspost/pgzip"
	"go.opentelemetry.io/otel"

	"github.com/chainguard-dev/go-apk/pkg/apk"
	"github.com/chainguard-dev/go-apk/pkg/tarball"
	"github.com/sigstore/cosign/v2/pkg/oci"
)

// pgzip's default is GOMAXPROCS(0)
//
// This is fine for single builds, but we will starve CPU for larger builds.
// 8 is our max because modern laptops tend to have ~8 performance cores, and
// large CI machines tend to have ~64 cores.
//
// This gives us near 100% utility on workstations, allows us to do ~8
// concurrent builds on giant machines, and uses only 1 core on tiny machines.
var pgzipThreads = min(runtime.GOMAXPROCS(0), 8)

func min(l, r int) int {
	if l < r {
		return l
	}

	return r
}

// BuildTarball takes the fully populated working directory and saves it to
// an OCI image layer tar.gz file.
func (bc *Context) BuildTarball(ctx context.Context) (string, hash.Hash, hash.Hash, int64, error) {
	ctx, span := otel.Tracer("apko").Start(ctx, "BuildTarball")
	defer span.End()

	var outfile *os.File
	var err error

	if bc.o.TarballPath != "" {
		outfile, err = os.Create(bc.o.TarballPath)
	} else {
		outfile, err = os.Create(filepath.Join(bc.o.TempDir(), bc.o.TarballFileName()))
	}
	if err != nil {
		return "", nil, nil, 0, fmt.Errorf("opening the build context tarball path failed: %w", err)
	}
	bc.o.TarballPath = outfile.Name()
	defer outfile.Close()

	// we use a general override of 0,0 for all files, but the specific overrides, that come from the installed package DB, come later
	tw, err := tarball.NewContext(
		tarball.WithSourceDateEpoch(bc.o.SourceDateEpoch),
	)
	if err != nil {
		return "", nil, nil, 0, fmt.Errorf("failed to construct tarball build context: %w", err)
	}

	digest := sha256.New()

	buf := bufio.NewWriterSize(outfile, 1<<22)
	gzw := gzip.NewWriter(io.MultiWriter(digest, buf))
	if err := gzw.SetConcurrency(1<<20, pgzipThreads); err != nil {
		return "", nil, nil, 0, fmt.Errorf("tried to set pgzip concurrency to %d: %w", pgzipThreads, err)
	}

	diffid := sha256.New()

	if err := tw.WriteTar(ctx, io.MultiWriter(diffid, gzw), bc.fs, bc.fs); err != nil {
		return "", nil, nil, 0, fmt.Errorf("failed to generate tarball for image: %w", err)
	}
	if err := gzw.Close(); err != nil {
		return "", nil, nil, 0, fmt.Errorf("closing gzip writer: %w", err)
	}

	if err := buf.Flush(); err != nil {
		return "", nil, nil, 0, fmt.Errorf("flushing %s: %w", outfile.Name(), err)
	}

	stat, err := outfile.Stat()
	if err != nil {
		return "", nil, nil, 0, fmt.Errorf("stat(%q): %w", outfile.Name(), err)
	}

	bc.Logger().Infof("built image layer tarball as %s", outfile.Name())
	return outfile.Name(), diffid, digest, stat.Size(), nil
}

func (bc *Context) buildImage(ctx context.Context) error {
	ctx, span := otel.Tracer("apko").Start(ctx, "buildImage")
	defer span.End()

	if bc.o.Lockfile != "" {
		lock, err := lock.FromFile(bc.o.Lockfile)
		if err != nil {
			return fmt.Errorf("failed to load lock-file: %w", err)
		}
		allPkgs, err := installablePackagesForArch(lock, bc.Arch())
		if err != nil {
			return fmt.Errorf("failed installation from lockfile %s: %w", bc.o.Lockfile, err)
		}
		return bc.apk.InstallPackages(ctx, &bc.o.SourceDateEpoch, allPkgs)
	} else {
		if err := bc.apk.FixateWorld(ctx, &bc.o.SourceDateEpoch); err != nil {
			return fmt.Errorf("installing apk packages: %w", err)
		}
	}

	if err := mutateAccounts(bc.fs, &bc.o, &bc.ic); err != nil {
		return fmt.Errorf("failed to mutate accounts: %w", err)
	}

	if err := mutatePaths(bc.fs, &bc.o, &bc.ic); err != nil {
		return fmt.Errorf("failed to mutate paths: %w", err)
	}

	if err := generateOSRelease(bc.fs, &bc.o, &bc.ic); errors.Is(err, ErrOSReleaseAlreadyPresent) {
		bc.Logger().Infof("did not generate /etc/os-release: %v", err)
	} else if err != nil {
		return fmt.Errorf("failed to generate /etc/os-release: %w", err)
	}

	if err := bc.s6.WriteSupervisionTree(bc.ic.Entrypoint.Services); err != nil {
		return fmt.Errorf("failed to write supervision tree: %w", err)
	}

	// add busybox symlinks
	installed, err := bc.apk.GetInstalled()
	if err != nil {
		return fmt.Errorf("getting installed packages: %w", err)
	}

	if err := installBusyboxLinks(bc.fs, installed); err != nil {
		return err
	}

	// add necessary character devices
	if err := installCharDevices(bc.fs); err != nil {
		return err
	}

	bc.Logger().Infof("finished building filesystem")

	return nil
}

// WriteIndex saves the index file from the given image configuration.
func WriteIndex(o *options.Options, idx oci.SignedImageIndex) (string, error) {
	outfile := filepath.Join(o.TempDir(), "index.json")

	b, err := idx.RawManifest()
	if err != nil {
		return "", fmt.Errorf("getting raw manifest: %w", err)
	}
	if err := os.WriteFile(outfile, b, 0644); err != nil { //nolint:gosec // this file is fine to be readable
		return "", fmt.Errorf("writing index file: %w", err)
	}
	o.Logger().Infof("built index file as %s", outfile)

	return outfile, nil
}

func (bc *Context) BuildPackageList(ctx context.Context) (toInstall []*apk.RepositoryPackage, conflicts []string, err error) {
	if toInstall, conflicts, err = bc.apk.ResolveWorld(ctx); err != nil {
		return toInstall, conflicts, fmt.Errorf("resolving apk packages: %w", err)
	}
	bc.Logger().Infof("finished gathering apk info")

	return toInstall, conflicts, err
}

func (bc *Context) Resolve(ctx context.Context) ([]*apk.APKResolved, error) {
	return bc.apk.ResolveAndCalculateWorld(ctx)
}

func (bc *Context) InstalledPackages() ([]*apk.InstalledPackage, error) {
	return bc.apk.GetInstalled()
}
