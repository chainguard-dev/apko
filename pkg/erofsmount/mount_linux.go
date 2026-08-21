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
	"syscall"
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
// The mount is recorded in a state file that Unmount reads back; that record
// is internal, so Mount reports only an error. On any error after a partial
// mount, all partially-completed mounts are torn down before returning.
func Mount(ctx context.Context, src Source, dest string, opts MountOptions) error {
	return mountWith(ctx, newDriver, src, dest, opts)
}

// mountWith is Mount with the driver constructor injected, so tests can drive
// the orchestration -- cleanup ordering, state file lifecycle -- with a fake.
func mountWith(ctx context.Context, newDrv driverFactory, src Source, dest string, opts MountOptions) error {
	log := clog.FromContext(ctx)

	absDest, err := filepath.Abs(dest)
	if err != nil {
		return fmt.Errorf("resolve dest: %w", err)
	}
	dest = filepath.Clean(absDest)

	if opts.Mode == "" {
		opts.Mode = string(modeAuto)
	}
	drv, err := newDrv(resolveMode(mode(opts.Mode)))
	if err != nil {
		return err
	}
	if err := drv.Preflight(); err != nil {
		return err
	}

	switch src.Kind {
	case KindBlob:
		return mountBlob(ctx, drv, src, dest, log)
	case KindOCIDir:
		return mountImage(ctx, drv, src, dest, opts, log)
	}
	return fmt.Errorf("unsupported source kind: %v", src.Kind)
}

func mountBlob(ctx context.Context, drv driver, src Source, dest string, log *clog.Logger) error {
	if err := ensureDir(dest); err != nil {
		return err
	}
	if _, err := drv.MountLayer(ctx, src.Path, dest); err != nil {
		return fmt.Errorf("mount %s at %s: %w", src.Path, dest, err)
	}
	log.Infof("mounted %s at %s (%s)", src.Path, dest, drv.Name())
	// No state file for raw blobs: there is no enclosing directory to put one
	// in. See Unmount for the matching teardown logic.
	return nil
}

func mountImage(ctx context.Context, drv driver, src Source, dest string, opts MountOptions, log *clog.Logger) (retErr error) {
	layers, err := ReadOCILayers(src.Path, src.Tag, opts.Arch)
	if err != nil {
		return err
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

	// Claim dest before mounting anything. An empty state file goes down
	// first and writeState replaces it at the end, so a second mount racing
	// for the same dest loses here rather than both of them proceeding.
	if err := ensureDir(dest); err != nil {
		return err
	}
	if err := claimState(dest); err != nil {
		return err
	}
	cleanups = append(cleanups, func() error { return removeState(dest) })

	// Single-layer read-only short-circuit: overlay buys nothing when there's
	// one lower and no upper, so mount the layer straight at DEST/merged.
	// Multi-layer and writable mounts still compose through overlayfs.
	if !opts.Writable && len(layers) == 1 {
		merged := filepath.Join(dest, "merged")
		if err := ensureDir(merged); err != nil {
			return err
		}
		umount, err := drv.MountLayer(ctx, layers[0].BlobPath, merged)
		if err != nil {
			return fmt.Errorf("mount layer 0 (%s) at %s: %w", layers[0].Digest, merged, err)
		}
		cleanups = append(cleanups, umount)
		log.Infof("mounted single layer (%s) read-only at %s", layers[0].Digest, merged)

		state := &mountState{
			SchemaVersion: stateSchemaVersion,
			Mode:          drv.Name(),
			Source:        src.Raw,
			Dest:          dest,
			Created:       time.Now().UTC(),
			Mounts:        []string{merged},
		}
		// Writable is false here by construction: this path only runs for a
		// read-only mount.
		if err := writeState(dest, state); err != nil {
			return fmt.Errorf("write state: %w", err)
		}
		return nil
	}

	// upper and work only exist for a writable mount; overlayfs takes a
	// lowerdir-only stack for the read-only case.
	subs := []string{"layers", "merged"}
	if opts.Writable {
		if err := checkUpperUnused(filepath.Join(dest, "upper")); err != nil {
			return err
		}
		subs = append(subs, "upper", "work")
	}
	for _, sub := range subs {
		if err := ensureDir(filepath.Join(dest, sub)); err != nil {
			return err
		}
	}

	layerMps := make([]string, 0, len(layers))
	mountsLIFO := make([]string, 0, len(layers)+1)
	for i, layer := range layers {
		mp := filepath.Join(dest, "layers", fmt.Sprintf("%02d", i))
		if err := ensureDir(mp); err != nil {
			return err
		}
		umount, err := drv.MountLayer(ctx, layer.BlobPath, mp)
		if err != nil {
			return fmt.Errorf("mount layer %d (%s) at %s: %w", i, layer.Digest, mp, err)
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
	umount, err := drv.AssembleOverlay(ctx, lowers, upper, work, merged, !opts.Writable)
	if err != nil {
		return fmt.Errorf("overlay merge into %s: %w", merged, err)
	}
	cleanups = append(cleanups, umount)
	mountsLIFO = append([]string{merged}, mountsLIFO...)
	log.Infof("merged %d layer(s) at %s", len(layers), merged)

	state := &mountState{
		SchemaVersion: stateSchemaVersion,
		Mode:          drv.Name(),
		Source:        src.Raw,
		Dest:          dest,
		Created:       time.Now().UTC(),
		Writable:      opts.Writable,
		Mounts:        mountsLIFO,
	}
	if err := writeState(dest, state); err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	return nil
}

// Unmount tears down a mount produced by Mount. For an image mount it reads
// the state file at <dest>/.apko-erofs-mount.json and unmounts in LIFO order;
// if the state file is absent it falls back to treating dest as a single
// (blob) mountpoint and runs umount/fusermount.
func Unmount(ctx context.Context, dest string) error {
	return unmountWith(ctx, newDriver, dest)
}

// unmountWith is Unmount with the driver constructor injected. See mountWith.
func unmountWith(ctx context.Context, newDrv driverFactory, dest string) error {
	log := clog.FromContext(ctx)
	absDest, err := filepath.Abs(dest)
	if err != nil {
		return fmt.Errorf("resolve dest: %w", err)
	}
	dest = filepath.Clean(absDest)

	st, err := loadState(dest)
	if err == nil {
		return unmountImage(ctx, newDrv, dest, st, log)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return unmountBlob(ctx, newDrv, dest, log)
}

func unmountImage(ctx context.Context, newDrv driverFactory, dest string, st *mountState, log *clog.Logger) error {
	drv, err := newDrv(st.Mode)
	if err != nil {
		return err
	}
	// checkResolved compares each mountpoint against dest with its own
	// symlinks resolved, so resolve dest once here.
	realDest, err := filepath.EvalSymlinks(dest)
	if err != nil {
		return fmt.Errorf("resolve dest %s: %w", dest, err)
	}
	// st.Mounts is overlay-first then per-layer mounts in LIFO order. If any
	// umount fails, stop: layer mounts that come after a still-pinned overlay
	// would only return EBUSY noise. Drop each entry as it comes down and
	// rewrite the state file if one fails, so the file always describes what
	// is still mounted -- without that a rerun starts again at merged, already
	// gone, and fails there without ever reaching the entry that was busy.
	// Rewrite what is left before returning any failure, so the file always
	// describes what is still mounted.
	stopped := func(err error) error {
		if werr := writeState(dest, st); werr != nil {
			log.Warnf("rewrite state after partial unmount: %v", werr)
		}
		return err
	}
	for len(st.Mounts) > 0 {
		mp := st.Mounts[0]
		// A rejection here is not something rerunning can clear, so it does
		// not get the "once they are no longer busy" hint below.
		if err := checkResolved(dest, realDest, mp); err != nil {
			return stopped(fmt.Errorf("refusing to umount %s: %w (%d mount(s) left in %s)",
				mp, err, len(st.Mounts), statePath(dest)))
		}
		if err := drv.Unmount(ctx, mp); err != nil {
			// The driver's error already names mp.
			return stopped(fmt.Errorf("%w (%d mount(s) still up; rerun `apko erofs umount %s` once they are no longer busy)",
				err, len(st.Mounts), dest))
		}
		st.Mounts = st.Mounts[1:]
		log.Infof("unmounted %s", mp)
	}
	for _, sub := range []string{"merged", "work", "layers"} {
		if err := os.RemoveAll(filepath.Join(dest, sub)); err != nil {
			log.Warnf("remove %s: %v", filepath.Join(dest, sub), err)
		}
	}
	// upper is the exception, and os.Remove rather than os.RemoveAll is the
	// whole point: it cannot delete a non-empty directory, so writes made
	// through the mount survive by construction and only an upper that was
	// never written to goes away. Leaving that empty directory behind would
	// make the next --rw mount at this dest refuse to start.
	upper := filepath.Join(dest, "upper")
	switch err := os.Remove(upper); {
	case err == nil, errors.Is(err, fs.ErrNotExist):
	case errors.Is(err, syscall.ENOTEMPTY), errors.Is(err, syscall.EEXIST):
		log.Infof("writes made through the mount are left in %s", upper)
	default:
		log.Warnf("remove %s: %v", upper, err)
	}
	if err := removeState(dest); err != nil {
		return fmt.Errorf("remove state file: %w", err)
	}
	return nil
}

// unmountBlob tears down a single mountpoint produced by mountBlob. Blobs have
// no state file, so the mode they were mounted with is unknown. The fuse
// driver's Unmount is already the kernel-umount-then-fusermount chain that
// covers both cases, so it is what we use here regardless of how the mount was
// made.
func unmountBlob(ctx context.Context, newDrv driverFactory, dest string, log *clog.Logger) error {
	drv, err := newDrv(modeFuse)
	if err != nil {
		return err
	}
	if err := drv.Unmount(ctx, dest); err != nil {
		// The driver's error already names dest.
		return err
	}
	log.Infof("unmounted %s", dest)
	return nil
}

// checkUpperUnused refuses to start a writable mount on top of an upperdir an
// earlier one left behind. Unmount keeps a written-through upper rather than
// discarding it, so reusing it here would stack one session's writes -- and
// the overlayfs metadata they carry, possibly for a different image -- over
// unrelated lowers, and the next umount would hand both back as one.
func checkUpperUnused(upper string) error {
	ents, err := os.ReadDir(upper)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", upper, err)
	}
	if len(ents) > 0 {
		return fmt.Errorf("%s is not empty (%d entries written through an earlier --rw mount); move or remove it first", upper, len(ents))
	}
	return nil
}

func ensureDir(path string) error {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", path, err)
	}
	// MkdirAll is satisfied by a symlink to an existing directory, so a link
	// planted at <dest>/merged would have the mount land wherever it points --
	// and Unmount, which requires the same path to resolve to itself, would
	// then refuse to take it back down. Only a real directory will do.
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is a %s, not a directory; refusing to mount there", path, fi.Mode().Type())
	}
	return nil
}
