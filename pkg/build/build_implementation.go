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
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	gzip "github.com/klauspost/pgzip"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"go.opentelemetry.io/otel"

	"github.com/chainguard-dev/clog"

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/apko/pkg/lock"
	"chainguard.dev/apko/pkg/options"
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

var pgzipPool = sync.Pool{
	New: func() interface{} {
		zw := gzip.NewWriter(nil)
		if err := zw.SetConcurrency(1<<20, pgzipThreads); err != nil {
			// This should never happen.
			panic(fmt.Errorf("tried to set pgzip concurrency to %d: %w", pgzipThreads, err))
		}
		return zw
	},
}

func pooledGzipWriter(w io.Writer) *gzip.Writer {
	zw := pgzipPool.Get().(*gzip.Writer)
	zw.Reset(w)
	return zw
}

var bufioPool = sync.Pool{
	New: func() interface{} {
		return bufio.NewWriterSize(nil, 1<<22)
	},
}

func pooledBufioWriter(w io.Writer) *bufio.Writer {
	bw := bufioPool.Get().(*bufio.Writer)
	bw.Reset(w)
	return bw
}

// BuildTarball takes the fully populated working directory and saves it to
// an OCI image layer tar.gz file.
func (bc *Context) BuildTarball(ctx context.Context) (string, hash.Hash, hash.Hash, int64, error) {
	log := clog.FromContext(ctx)

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

	digest := sha256.New()

	buf := pooledBufioWriter(outfile)
	defer bufioPool.Put(buf)

	gzw := pooledGzipWriter(io.MultiWriter(digest, buf))
	defer pgzipPool.Put(gzw)

	diffid := sha256.New()

	if err := writeTar(ctx, io.MultiWriter(diffid, gzw), bc.fs); err != nil {
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

	log.Infof("built image layer tarball as %s", outfile.Name())
	return outfile.Name(), diffid, digest, stat.Size(), nil
}

func (bc *Context) buildImage(ctx context.Context) error {
	log := clog.FromContext(ctx)

	// When using base image for the build, apko adds new layer on top of the base. This means
	// it will override files from lower layers. We add all installed packages from base to current
	// installed file so that the final installed file contains all image's packages.
	if bc.baseimg != nil {
		basePkgs := bc.baseimg.InstalledPackages()
		// Index for loop to make golang-ci happy.
		// See https://stackoverflow.com/questions/62446118/implicit-memory-aliasing-in-for-loop
		for index := range basePkgs {
			err := bc.apk.AddInstalledPackage(&basePkgs[index].Package, basePkgs[index].Files)
			if err != nil {
				return err
			}
		}
	}

	if bc.o.Lockfile != "" {
		lock, err := lock.FromFile(bc.o.Lockfile)
		if err != nil {
			return fmt.Errorf("failed to load lock-file: %w", err)
		}
		if lock.Config == nil {
			log.Warnf("The lock file does not contain checksum of the config. Please regenerate.")
		} else if bc.o.ImageConfigChecksum != "" && bc.o.ImageConfigChecksum != lock.Config.DeepChecksum {
			return fmt.Errorf("checksum in the lock file '%v' does not matches the original config: '%v' "+
				"(maybe regenerate the lock file)",
				bc.o.Lockfile, bc.o.ImageConfigFile)
		}
		allPkgs, err := installablePackagesForArch(lock, bc.Arch())
		if err != nil {
			return fmt.Errorf("failed getting packages for install from lockfile %s: %w", bc.o.Lockfile, err)
		}
		err = bc.apk.InstallPackages(ctx, &bc.o.SourceDateEpoch, allPkgs)
		if err != nil {
			return fmt.Errorf("failed installation from lockfile %s: %w", bc.o.Lockfile, err)
		}
	} else {
		if err := bc.apk.FixateWorld(ctx, &bc.o.SourceDateEpoch); err != nil {
			return fmt.Errorf("installing apk packages: %w", err)
		}
	}

	// For now adding additional accounts is banned when using base image. On the other hand, we don't want to
	// wipe out the users set in base.
	// If one wants to add a support for adding additional users they would need to look into this piece of code.
	if bc.ic.Contents.BaseImage == nil {
		if err := mutateAccounts(bc.fs, &bc.ic); err != nil {
			return fmt.Errorf("failed to mutate accounts: %w", err)
		}
	}

	if err := bc.WriteEtcApkoConfig(ctx); err != nil {
		return fmt.Errorf("failed to install apko config: %w", err)
	}

	if err := mutatePaths(bc.fs, &bc.o, &bc.ic); err != nil {
		return fmt.Errorf("failed to mutate paths: %w", err)
	}

	if err := bc.s6.WriteSupervisionTree(ctx, bc.ic.Entrypoint.Services); err != nil {
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

	log.Debug("finished building filesystem")

	return nil
}

func (bc *Context) WriteEtcApkoConfig(_ context.Context) error {
	// Encode the image configuration and write it to /etc/apko.json
	f, err := bc.fs.Create("/etc/apko.json")
	if err != nil {
		return fmt.Errorf("creating /etc/apko.json: %w", err)
	}
	if err := json.NewEncoder(f).Encode(bc.ic); err != nil {
		return fmt.Errorf("encoding image config: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing /etc/apko.json: %w", err)
	}
	if err := bc.fs.Chmod("/etc/apko.json", 0444); err != nil {
		return fmt.Errorf("chmod /etc/apko.json: %w", err)
	}
	return nil
}

// WriteIndex saves the index file from the given image configuration.
func WriteIndex(ctx context.Context, o *options.Options, idx oci.SignedImageIndex) (string, error) {
	log := clog.FromContext(ctx)
	outfile := filepath.Join(o.TempDir(), "index.json")

	b, err := idx.RawManifest()
	if err != nil {
		return "", fmt.Errorf("getting raw manifest: %w", err)
	}
	if err := os.WriteFile(outfile, b, 0644); err != nil { //nolint:gosec // this file is fine to be readable
		return "", fmt.Errorf("writing index file: %w", err)
	}
	log.Infof("built index file as %s", outfile)

	return outfile, nil
}

func (bc *Context) BuildPackageList(ctx context.Context) (toInstall []*apk.RepositoryPackage, conflicts []string, err error) {
	log := clog.FromContext(ctx)
	if toInstall, conflicts, err = bc.apk.ResolveWorld(ctx); err != nil {
		return toInstall, conflicts, fmt.Errorf("resolving apk packages: %w", err)
	}
	log.Infof("finished gathering apk info")

	return toInstall, conflicts, err
}

func (bc *Context) Resolve(ctx context.Context) ([]*apk.APKResolved, error) {
	return bc.apk.ResolveAndCalculateWorld(ctx)
}

func (bc *Context) ResolveWithBase(ctx context.Context) ([]*apk.APKResolved, error) {
	// Firstly, resolve the world with all packages. When using base image, the world file contains
	// all packages from base as well. It's important that ResolveWorld operates on APKINDEX files only
	// and doesn't fetch actual packages.
	allPkgs, _, err := bc.apk.ResolveWorld(ctx)
	if err != nil {
		return nil, err
	}
	var existingPkgs []*apk.InstalledPackage
	if bc.baseimg != nil {
		existingPkgs = bc.baseimg.InstalledPackages()
	}

	var toInstall []*apk.RepositoryPackage
	for _, pkg := range allPkgs {
		inBase := false
		for _, existingPkg := range existingPkgs {
			if pkg.Name == existingPkg.Name {
				inBase = true
			}
		}
		if !inBase {
			toInstall = append(toInstall, pkg)
		}
	}
	// Note: CalculateWorld fetches the packages - they have to be available in the repository.
	resolvedPkgs, err := bc.apk.CalculateWorld(ctx, toInstall)
	if err != nil {
		return nil, err
	}
	return resolvedPkgs, nil
}

func (bc *Context) InstalledPackages() ([]*apk.InstalledPackage, error) {
	return bc.apk.GetInstalled()
}
