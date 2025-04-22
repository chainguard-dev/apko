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
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/chainguard-dev/clog"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	gzip "github.com/klauspost/pgzip"
	"github.com/sigstore/cosign/v2/pkg/oci"

	ldsocache "chainguard.dev/apko/internal/ldso-cache"
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

// layerWriter allows lazily writing files to a tarball instead
// of doing everything in one pass, this is necessary for multi-layer
// images where we are writing to multiple layers at the same time.
type layerWriter struct {
	w        *tar.Writer
	stack    []*file // only used by multi-layer builds
	finalize func() (*layer, error)
}

// newLayerWriter wraps a file with a gzipping tar writer that computes
// everything we need to know to implement a v1.Layer, which it will
// produce when finalize() is called.
func newLayerWriter(out *os.File) *layerWriter {
	digest := sha256.New()

	buf := pooledBufioWriter(out)

	gzw := pooledGzipWriter(io.MultiWriter(digest, buf))

	diffid := sha256.New()

	w := tar.NewWriter(io.MultiWriter(diffid, gzw))

	// Just capturing everything in a closure here is more straightforward
	// to read (as a translation from what used to implement this) than
	// adding a bunch of fields to layerWriter.
	return &layerWriter{
		w: w,
		finalize: func() (*layer, error) {
			defer pgzipPool.Put(gzw)
			defer bufioPool.Put(buf)

			if err := w.Close(); err != nil {
				return nil, fmt.Errorf("closing tar writer: %w", err)
			}

			if err := gzw.Close(); err != nil {
				return nil, fmt.Errorf("closing gzip writer: %w", err)
			}

			if err := buf.Flush(); err != nil {
				return nil, fmt.Errorf("flushing %s: %w", out.Name(), err)
			}

			stat, err := out.Stat()
			if err != nil {
				return nil, fmt.Errorf("statting %s: %w", out.Name(), err)
			}

			h := v1.Hash{
				Algorithm: "sha256",
				Hex:       hex.EncodeToString(digest.Sum(make([]byte, 0, digest.Size()))),
			}

			l := &layer{
				filename: out.Name(),
				desc: &v1.Descriptor{
					Digest:    h,
					Size:      stat.Size(),
					MediaType: v1types.OCILayer,
				},
				diffid: &v1.Hash{
					Algorithm: "sha256",
					Hex:       hex.EncodeToString(diffid.Sum(make([]byte, 0, diffid.Size()))),
				},
			}

			return l, nil
		},
	}
}

func (bc *Context) buildImage(ctx context.Context) ([]*apk.Package, error) {
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
				return nil, err
			}
		}
	}

	var (
		pkgs []*apk.Package
		err  error
	)
	if bc.o.Lockfile != "" {
		lock, err := lock.FromFile(bc.o.Lockfile)
		if err != nil {
			return nil, fmt.Errorf("failed to load lock-file: %w", err)
		}
		if lock.Config == nil {
			log.Warnf("The lock file does not contain checksum of the config. Please regenerate.")
		} else if bc.o.ImageConfigChecksum != "" && bc.o.ImageConfigChecksum != lock.Config.DeepChecksum {
			return nil, fmt.Errorf("checksum in the lock file '%v' does not matches the original config: '%v' "+
				"(maybe regenerate the lock file)",
				bc.o.Lockfile, bc.o.ImageConfigFile)
		}
		allPkgs, err := installablePackagesForArch(lock, bc.Arch())
		if err != nil {
			return nil, fmt.Errorf("failed getting packages for install from lockfile %s: %w", bc.o.Lockfile, err)
		}
		pkgs, err = bc.apk.InstallPackages(ctx, &bc.o.SourceDateEpoch, allPkgs)
		if err != nil {
			return nil, fmt.Errorf("failed installation from lockfile %s: %w", bc.o.Lockfile, err)
		}
	} else {
		pkgs, err = bc.apk.FixateWorld(ctx, &bc.o.SourceDateEpoch)
		if err != nil {
			return nil, fmt.Errorf("installing apk packages: %w", err)
		}
	}

	// For now adding additional accounts is banned when using base image. On the other hand, we don't want to
	// wipe out the users set in base.
	// If one wants to add a support for adding additional users they would need to look into this piece of code.
	if bc.ic.Contents.BaseImage == nil {
		if err := mutateAccounts(bc.fs, &bc.ic); err != nil {
			return nil, fmt.Errorf("failed to mutate accounts: %w", err)
		}
	}

	if err := bc.WriteEtcApkoConfig(ctx); err != nil {
		return nil, fmt.Errorf("failed to install apko config: %w", err)
	}

	if err := mutatePaths(bc.fs, &bc.o, &bc.ic); err != nil {
		return nil, fmt.Errorf("failed to mutate paths: %w", err)
	}

	if err := bc.s6.WriteSupervisionTree(ctx, bc.ic.Entrypoint.Services); err != nil {
		return nil, fmt.Errorf("failed to write supervision tree: %w", err)
	}

	// add busybox symlinks
	installed, err := bc.apk.GetInstalled()
	if err != nil {
		return nil, fmt.Errorf("getting installed packages: %w", err)
	}

	if err := installBusyboxLinks(bc.fs, installed); err != nil {
		return nil, err
	}

	// add necessary character devices
	if err := installCharDevices(bc.fs); err != nil {
		return nil, err
	}

	if _, err := bc.fs.Stat("etc/ld.so.conf"); err == nil {
		log.Debug("updating /etc/ld.so.cache")
		libdirs := []string{"/lib"}
		dirs, err := ldsocache.ParseLDSOConf(bc.fs, "etc/ld.so.conf")
		if err != nil {
			return nil, err
		}
		libdirs = append(libdirs, dirs...)
		cacheFile, err := ldsocache.BuildCacheFileForDirs(
			bc.fs, libdirs,
		)
		if err != nil {
			return nil, fmt.Errorf("failed generating ldsocache")
		}
		lsc, err := bc.fs.Create("etc/ld.so.cache")
		if err != nil {
			return nil, fmt.Errorf("unable to create /etc/ld.so.cache")
		}
		err = cacheFile.Write(lsc)
		if err != nil {
			return nil, fmt.Errorf("unable to write /etc/ld.so.cache")
		}
	} else {
		log.Debug("/etc/ld.so.conf not found, skipping /etc/ld.so.cache update")
	}

	log.Debug("finished building filesystem")

	return pkgs, nil
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
