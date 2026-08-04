// Copyright 2026 Chainguard, Inc.
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

//go:build linux

package erofsmount

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/chainguard-dev/clog"
)

// Mount mounts src at dest. For KindBlob, dest is the single mountpoint. For
// KindOCIDir, dest is a directory that receives the standard layout:
//
//	<dest>/layers/00..NN  per-layer EROFS mounts (00 is base)
//	<dest>/upper          overlayfs upperdir (writable mounts only)
//	<dest>/work           overlayfs workdir (writable mounts only)
//	<dest>/merged         overlayfs merged view
//	<dest>/.apko-erofs-mount.json  state record for Unmount
//
// On success, Mount returns the recorded MountState. On any error after a
// partial mount, all partially-completed mounts are torn down before
// returning.
func Mount(ctx context.Context, src Source, dest string, opts Options) (st *MountState, retErr error) {
	log := clog.FromContext(ctx)

	absDest, err := filepath.Abs(dest)
	if err != nil {
		return nil, fmt.Errorf("resolve dest: %w", err)
	}
	dest = filepath.Clean(absDest)

	if opts.Mode == "" {
		opts.Mode = ModeAuto
	}
	mode := ResolveMode(opts.Mode)
	drv, err := NewDriver(mode)
	if err != nil {
		return nil, err
	}
	if err := drv.Preflight(); err != nil {
		return nil, err
	}

	switch src.Kind {
	case KindBlob:
		return mountBlob(ctx, drv, src, dest, log)
	case KindOCIDir:
		return mountImage(ctx, drv, src, dest, opts, log)
	}
	return nil, fmt.Errorf("unsupported source kind: %v", src.Kind)
}

func mountBlob(ctx context.Context, drv Driver, src Source, dest string, log *clog.Logger) (*MountState, error) {
	if err := ensureDir(dest); err != nil {
		return nil, err
	}
	if _, err := drv.MountLayer(ctx, src.Path, dest); err != nil {
		return nil, fmt.Errorf("mount %s at %s: %w", src.Path, dest, err)
	}
	log.Infof("mounted %s at %s (%s)", src.Path, dest, drv.Name())
	// No state file for raw blobs — see Unmount for the matching teardown
	// logic. Return a state value for completeness but do not persist it.
	return &MountState{
		SchemaVersion: StateSchemaVersion,
		Mode:          drv.Name(),
		Source:        src.Raw,
		Dest:          dest,
		Created:       time.Now().UTC(),
		Mounts:        []string{dest},
	}, nil
}

func mountImage(ctx context.Context, drv Driver, src Source, dest string, opts Options, log *clog.Logger) (st *MountState, retErr error) {
	layers, err := ReadOCILayers(src.Path, src.Tag, opts.Arch)
	if err != nil {
		return nil, err
	}

	// Refuse to clobber an existing mount.
	if _, err := os.Stat(StatePath(dest)); err == nil {
		return nil, fmt.Errorf("dest %s already has a mount state file (%s); umount first", dest, StatePath(dest))
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("stat state file: %w", err)
	}

	var cleanups []func() error
	defer func() {
		if retErr == nil {
			return
		}
		for _, c := range slices.Backward(cleanups) {
			if err := c(); err != nil {
				log.Warnf("cleanup on error: %v", err)
			}
		}
	}()

	// Single-layer read-only short-circuit: overlay buys nothing when there's
	// one lower and no upper, and a lowerdir-only overlay over a single
	// EROFS mount has been flaky across overlayfs versions. Mount the layer
	// straight at DEST/merged.
	if opts.ReadOnly && len(layers) == 1 {
		merged := filepath.Join(dest, "merged")
		if err := ensureDir(merged); err != nil {
			return nil, err
		}
		umount, err := drv.MountLayer(ctx, layers[0].BlobPath, merged)
		if err != nil {
			return nil, fmt.Errorf("mount layer 0 (%s) at %s: %w", layers[0].Digest, merged, err)
		}
		cleanups = append(cleanups, umount)
		log.Infof("mounted single layer (%s) read-only at %s", layers[0].Digest, merged)

		state := &MountState{
			SchemaVersion: StateSchemaVersion,
			Mode:          drv.Name(),
			Source:        src.Raw,
			Dest:          dest,
			Created:       time.Now().UTC(),
			Mounts:        []string{merged},
		}
		if err := WriteState(dest, state); err != nil {
			return nil, fmt.Errorf("write state: %w", err)
		}
		return state, nil
	}

	for _, sub := range []string{"layers", "upper", "work", "merged"} {
		if err := ensureDir(filepath.Join(dest, sub)); err != nil {
			return nil, err
		}
	}

	layerMps := make([]string, 0, len(layers))
	mountsLIFO := make([]string, 0, len(layers)+1)
	for i, layer := range layers {
		mp := filepath.Join(dest, "layers", fmt.Sprintf("%02d", i))
		if err := ensureDir(mp); err != nil {
			return nil, err
		}
		umount, err := drv.MountLayer(ctx, layer.BlobPath, mp)
		if err != nil {
			return nil, fmt.Errorf("mount layer %d (%s) at %s: %w", i, layer.Digest, mp, err)
		}
		cleanups = append(cleanups, umount)
		layerMps = append(layerMps, mp)
		mountsLIFO = append([]string{mp}, mountsLIFO...)
		log.Infof("mounted layer %d (%s) at %s", i, layer.Digest, mp)
	}

	// overlayfs lowerdir is highest-priority first; OCI is bottom-up so we
	// reverse.
	lowers := make([]string, len(layerMps))
	for i := range layerMps {
		lowers[i] = layerMps[len(layerMps)-1-i]
	}

	upper := filepath.Join(dest, "upper")
	work := filepath.Join(dest, "work")
	merged := filepath.Join(dest, "merged")
	umount, err := drv.AssembleOverlay(ctx, lowers, upper, work, merged, opts.ReadOnly)
	if err != nil {
		return nil, fmt.Errorf("overlay merge into %s: %w", merged, err)
	}
	cleanups = append(cleanups, umount)
	mountsLIFO = append([]string{merged}, mountsLIFO...)
	log.Infof("merged %d layer(s) at %s", len(layers), merged)

	state := &MountState{
		SchemaVersion: StateSchemaVersion,
		Mode:          drv.Name(),
		Source:        src.Raw,
		Dest:          dest,
		Created:       time.Now().UTC(),
		Mounts:        mountsLIFO,
	}
	if err := WriteState(dest, state); err != nil {
		return nil, fmt.Errorf("write state: %w", err)
	}
	return state, nil
}

// Unmount tears down a mount produced by Mount. For an image mount it reads
// the state file at <dest>/.apko-erofs-mount.json and unmounts in LIFO order;
// if the state file is absent it falls back to treating dest as a single
// (blob) mountpoint and runs umount/fusermount.
func Unmount(ctx context.Context, dest string) error {
	log := clog.FromContext(ctx)
	absDest, err := filepath.Abs(dest)
	if err != nil {
		return fmt.Errorf("resolve dest: %w", err)
	}
	dest = filepath.Clean(absDest)

	st, err := LoadState(dest)
	if err == nil {
		return unmountImage(ctx, dest, st, log)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return unmountBlob(ctx, dest, log)
}

func unmountImage(ctx context.Context, dest string, st *MountState, log *clog.Logger) error {
	drv, err := NewDriver(st.Mode)
	if err != nil {
		return err
	}
	// st.Mounts is overlay-first then per-layer mounts in LIFO order. If
	// any umount fails, stop: layer mounts that come after a still-pinned
	// overlay would only return EBUSY noise, and continuing past an error
	// would also leave the state file out of sync with reality. The user
	// can rerun `apko erofs umount` after addressing whatever is keeping
	// the mount busy.
	for _, mp := range st.Mounts {
		if err := unmountOne(ctx, drv, mp); err != nil {
			return fmt.Errorf("umount %s: %w (remaining mounts left intact; rerun once they are no longer busy)", mp, err)
		}
		log.Infof("unmounted %s", mp)
	}
	for _, sub := range []string{"merged", "upper", "work", "layers"} {
		if err := os.RemoveAll(filepath.Join(dest, sub)); err != nil {
			log.Warnf("remove %s: %v", filepath.Join(dest, sub), err)
		}
	}
	if err := RemoveState(dest); err != nil {
		return fmt.Errorf("remove state file: %w", err)
	}
	return nil
}

// unmountBlob tears down a single mountpoint produced by mountBlob. Since
// blobs do not have a state file we have to guess which umount tool applies;
// we try kernel umount first (which works for both kernel-erofs and any
// kernel-overlay-over-fuse cases by transitively triggering fuse teardown
// where appropriate) and fall back to fusermount.
func unmountBlob(ctx context.Context, dest string, log *clog.Logger) error {
	if err := runCmd(ctx, "umount", dest); err == nil {
		log.Infof("unmounted %s", dest)
		return nil
	}
	fm, err := lookupFusermount()
	if err != nil {
		return fmt.Errorf("umount %s: kernel umount failed and no fusermount available", dest)
	}
	if err := runCmd(ctx, fm, "-u", dest); err != nil {
		return fmt.Errorf("umount %s: %w", dest, err)
	}
	log.Infof("unmounted %s", dest)
	return nil
}

// unmountOne unmounts mp using the appropriate tool for the recorded driver.
// We don't try to be clever about kernel-vs-fuse here beyond what the state
// file tells us; if the user mounted with kernel they need kernel umount.
func unmountOne(ctx context.Context, drv Driver, mp string) error {
	switch drv.Name() {
	case ModeKernel:
		return runCmd(ctx, "umount", mp)
	case ModeFuse:
		// For fuse mounts: the merged view may itself be a kernel overlay
		// (when overlayfs over FUSE worked) or a fuse-overlayfs mount.
		// `umount` handles both kernel-side overlays; `fusermount -u`
		// handles fuse-overlayfs and the per-layer erofsfuse mounts. Try
		// kernel umount first (cheap, no-op if not applicable), then
		// fusermount.
		if err := runCmd(ctx, "umount", mp); err == nil {
			return nil
		}
		fm, err := lookupFusermount()
		if err != nil {
			return err
		}
		return runCmd(ctx, fm, "-u", mp)
	}
	return fmt.Errorf("unknown mode %q", drv.Name())
}

func ensureDir(path string) error {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", path, err)
	}
	return nil
}
