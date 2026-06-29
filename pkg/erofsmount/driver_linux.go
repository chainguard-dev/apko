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
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/chainguard-dev/clog"
)

// Driver wraps the externally-invoked mount and umount commands used by Mount.
// Two implementations exist on Linux: kernelDriver shells out to mount(8) and
// umount(8); fuseDriver shells out to erofsfuse and fusermount.
type Driver interface {
	// Name returns the resolved mode (kernel or fuse), never auto.
	Name() Mode
	// Preflight verifies that the required binaries exist and that the
	// invoking process can plausibly perform mounts in this mode (e.g.
	// kernelDriver requires euid 0). It must be called before any
	// MountLayer/AssembleOverlay calls.
	Preflight() error
	// MountLayer mounts blob (a raw EROFS image) read-only at mp. The
	// returned umount closure tears down that single mount.
	MountLayer(ctx context.Context, blob, mp string) (func() error, error)
	// AssembleOverlay layers `lowers` (in overlayfs priority order — top
	// first, bottom last) on top of upper/work into merged. When readOnly is
	// true, upper and work are ignored and the overlay is built as
	// lowerdir-only (which overlayfs supports for read-only stacks).
	AssembleOverlay(ctx context.Context, lowers []string, upper, work, merged string, readOnly bool) (func() error, error)
}

// NewDriver returns the driver that corresponds to mode. mode must be one of
// ModeKernel or ModeFuse — ModeAuto must be resolved by the caller via
// ResolveMode before calling NewDriver.
func NewDriver(mode Mode) (Driver, error) {
	switch mode {
	case ModeKernel:
		return &kernelDriver{}, nil
	case ModeFuse:
		return &fuseDriver{}, nil
	}
	return nil, fmt.Errorf("unknown mount mode %q", mode)
}

// ResolveMode collapses ModeAuto into ModeKernel (euid 0) or ModeFuse.
func ResolveMode(req Mode) Mode {
	if req != ModeAuto {
		return req
	}
	if os.Geteuid() == 0 {
		return ModeKernel
	}
	return ModeFuse
}

// kernelDriver

type kernelDriver struct{}

func (kernelDriver) Name() Mode { return ModeKernel }

func (kernelDriver) Preflight() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("kernel mount mode requires root (euid 0); pass --mode=fuse to use erofsfuse instead")
	}
	for _, bin := range []string{"mount", "umount"} {
		if _, err := exec.LookPath(bin); err != nil {
			return fmt.Errorf("%s not found in PATH: %w", bin, err)
		}
	}
	return nil
}

func (d *kernelDriver) MountLayer(ctx context.Context, blob, mp string) (func() error, error) {
	args := buildKernelLayerArgs(blob, mp)
	if err := runCmd(ctx, args[0], args[1:]...); err != nil {
		return nil, err
	}
	return func() error {
		uargs := buildKernelUmountArgs(mp)
		return runCmd(context.Background(), uargs[0], uargs[1:]...)
	}, nil
}

func (d *kernelDriver) AssembleOverlay(ctx context.Context, lowers []string, upper, work, merged string, readOnly bool) (func() error, error) {
	args := buildKernelOverlayArgs(lowers, upper, work, merged, readOnly)
	if err := runCmd(ctx, args[0], args[1:]...); err != nil {
		return nil, err
	}
	return func() error {
		uargs := buildKernelUmountArgs(merged)
		return runCmd(context.Background(), uargs[0], uargs[1:]...)
	}, nil
}

// fuseDriver

type fuseDriver struct{}

func (fuseDriver) Name() Mode { return ModeFuse }

func (fuseDriver) Preflight() error {
	if _, err := exec.LookPath("erofsfuse"); err != nil {
		return fmt.Errorf("erofsfuse not found in PATH (install erofs-utils-fuse): %w", err)
	}
	if _, err := lookupFusermount(); err != nil {
		return err
	}
	return nil
}

func (d *fuseDriver) MountLayer(ctx context.Context, blob, mp string) (func() error, error) {
	args := buildFuseLayerArgs(blob, mp)
	if err := runCmd(ctx, args[0], args[1:]...); err != nil {
		return nil, err
	}
	return func() error {
		fm, err := lookupFusermount()
		if err != nil {
			return err
		}
		uargs := buildFusermountUmountArgs(fm, mp)
		return runCmd(context.Background(), uargs[0], uargs[1:]...)
	}, nil
}

func (d *fuseDriver) AssembleOverlay(ctx context.Context, lowers []string, upper, work, merged string, readOnly bool) (func() error, error) {
	// First try the kernel overlay driver on top of the FUSE lowerdirs. Modern
	// kernels (~5.11+) allow this in user namespaces. If that fails, fall back
	// to fuse-overlayfs.
	kArgs := buildKernelOverlayArgs(lowers, upper, work, merged, readOnly)
	if err := runCmd(ctx, kArgs[0], kArgs[1:]...); err == nil {
		return func() error {
			uargs := buildKernelUmountArgs(merged)
			return runCmd(context.Background(), uargs[0], uargs[1:]...)
		}, nil
	}

	if _, err := exec.LookPath("fuse-overlayfs"); err != nil {
		return nil, fmt.Errorf("kernel overlay failed and fuse-overlayfs is not installed: %w", err)
	}
	fArgs := buildFuseOverlayArgs(lowers, upper, work, merged, readOnly)
	if err := runCmd(ctx, fArgs[0], fArgs[1:]...); err != nil {
		return nil, err
	}
	return func() error {
		fm, err := lookupFusermount()
		if err != nil {
			return err
		}
		uargs := buildFusermountUmountArgs(fm, merged)
		return runCmd(context.Background(), uargs[0], uargs[1:]...)
	}, nil
}

// Command builders. Pure functions so they can be tested without exec.

func buildKernelLayerArgs(blob, mp string) []string {
	// "-o loop" is unnecessary on modern util-linux: when the source is a
	// regular file, mount(8) auto-detects and allocates a loop device with
	// O_AUTOCLEAR so it's freed on umount. Asking for "-o loop" explicitly
	// risks leaking the loop device when the kernel/util-linux don't agree
	// on autoclear semantics. EROFS itself is read-only, but pass "-o ro"
	// anyway to document intent.
	return []string{"mount", "-t", "erofs", "-o", "ro", blob, mp}
}

func buildKernelUmountArgs(mp string) []string {
	return []string{"umount", mp}
}

func buildFuseLayerArgs(blob, mp string) []string {
	return []string{"erofsfuse", blob, mp}
}

func buildFusermountUmountArgs(fusermountBin, mp string) []string {
	return []string{fusermountBin, "-u", mp}
}

func buildKernelOverlayArgs(lowers []string, upper, work, merged string, readOnly bool) []string {
	opts := "lowerdir=" + strings.Join(lowers, ":")
	if !readOnly {
		opts += ",upperdir=" + upper + ",workdir=" + work
	} else {
		opts += ",ro"
	}
	return []string{"mount", "-t", "overlay", "-o", opts, "overlay", merged}
}

func buildFuseOverlayArgs(lowers []string, upper, work, merged string, readOnly bool) []string {
	opts := "lowerdir=" + strings.Join(lowers, ":")
	if !readOnly {
		opts += ",upperdir=" + upper + ",workdir=" + work
	}
	return []string{"fuse-overlayfs", "-o", opts, merged}
}

// lookupFusermount returns the path to whichever of `fusermount3` or
// `fusermount` is available, preferring fusermount3 since it matches modern
// libfuse builds.
func lookupFusermount() (string, error) {
	for _, name := range []string{"fusermount3", "fusermount"} {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}
	return "", errors.New("neither fusermount3 nor fusermount found in PATH")
}

// runCmd runs name+args, captures stderr, and wraps any error with the
// captured stderr so users see what mount(8) actually said.
func runCmd(ctx context.Context, name string, args ...string) error {
	log := clog.FromContext(ctx)
	cmd := exec.CommandContext(ctx, name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	log.Debugf("exec: %s %s", name, strings.Join(args, " "))
	if err := cmd.Run(); err != nil {
		stderrTrim := strings.TrimSpace(stderr.String())
		if stderrTrim != "" {
			return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, stderrTrim)
		}
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}
