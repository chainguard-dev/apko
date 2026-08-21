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
	"golang.org/x/sys/unix"
)

// driver wraps the mount and umount operations used by Mount. Two
// implementations exist on Linux: kernelDriver shells out to mount(8) and
// unmounts with umount(2) directly; fuseDriver shells out to erofsfuse and
// fusermount, trying the kernel unmount first.
type driver interface {
	// Name returns the resolved mode (kernel or fuse), never auto.
	Name() mode
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
	// Unmount tears down a single mountpoint with the tool this driver
	// mounts with. Unlike the closures returned by MountLayer and
	// AssembleOverlay it needs no prior call in this process, so it is what
	// Unmount uses when working from a state file.
	Unmount(ctx context.Context, mp string) error
}

// driverFactory builds the driver for a mode. Mount and Unmount pass newDriver;
// tests pass a factory returning a fake, which is the only way to exercise the
// mount and unmount orchestration without root and real filesystems.
type driverFactory func(m mode) (driver, error)

// newDriver returns the driver that corresponds to m. m must be one of
// modeKernel or modeFuse — modeAuto must be resolved by the caller via
// resolveMode before calling newDriver.
func newDriver(m mode) (driver, error) {
	switch m {
	case modeKernel:
		return &kernelDriver{}, nil
	case modeFuse:
		return &fuseDriver{}, nil
	}
	return nil, fmt.Errorf("unknown mount mode %q", m)
}

// resolveMode collapses modeAuto into modeKernel (euid 0) or modeFuse.
func resolveMode(req mode) mode {
	if req != modeAuto {
		return req
	}
	if os.Geteuid() == 0 {
		return modeKernel
	}
	return modeFuse
}

// kernelDriver

type kernelDriver struct{}

func (kernelDriver) Name() mode { return modeKernel }

func (kernelDriver) Preflight() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("kernel mount mode requires root (euid 0); pass --mode=fuse to use erofsfuse instead")
	}
	// Only mount(8) is execed; unmounting goes through umount(2) directly,
	// so umount(8) is no longer a requirement.
	if _, err := exec.LookPath("mount"); err != nil {
		return fmt.Errorf("mount not found in PATH: %w", err)
	}
	return nil
}

func (d *kernelDriver) MountLayer(ctx context.Context, blob, mp string) (func() error, error) {
	args := buildKernelLayerArgs(blob, mp)
	if err := runCmd(ctx, args[0], args[1:]...); err != nil {
		return nil, err
	}
	return func() error {
		return kernelUnmount(context.Background(), mp)
	}, nil
}

func (d *kernelDriver) Unmount(ctx context.Context, mp string) error {
	return kernelUnmount(ctx, mp)
}

func (d *kernelDriver) AssembleOverlay(ctx context.Context, lowers []string, upper, work, merged string, readOnly bool) (func() error, error) {
	args := buildKernelOverlayArgs(lowers, upper, work, merged, readOnly)
	if err := runCmd(ctx, args[0], args[1:]...); err != nil {
		return nil, err
	}
	return func() error {
		return kernelUnmount(context.Background(), merged)
	}, nil
}

// fuseDriver

type fuseDriver struct{}

func (fuseDriver) Name() mode { return modeFuse }

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

// Unmount tries kernel umount before fusermount. A merged view mounted in fuse
// mode may itself be a kernel overlay (when overlayfs over FUSE worked) or a
// fuse-overlayfs mount, and per-layer mounts are erofsfuse; umount handles the
// first, fusermount -u the other two.
//
// Both failures are reported. Unmount is also the fall-back for a blob mount,
// whose mode is unknown, so the kernel attempt is the one that failed for the
// interesting reason -- returning only the fusermount error turns "target is
// busy" into "neither fusermount3 nor fusermount found in PATH".
func (d *fuseDriver) Unmount(ctx context.Context, mp string) error {
	kerr := kernelUnmount(ctx, mp)
	if kerr == nil {
		return nil
	}
	// A symlinked mountpoint is a refusal, not a sign that the wrong tool was
	// tried. fusermount carries its own UMOUNT_NOFOLLOW and would only refuse
	// it again, so running it adds nothing and buries the reason in a join.
	if errors.Is(kerr, errSymlinkedMountpoint) {
		return kerr
	}
	fm, err := lookupFusermount()
	if err != nil {
		return errors.Join(kerr, err)
	}
	fargs := buildFusermountUmountArgs(fm, mp)
	if ferr := runCmd(ctx, fargs[0], fargs[1:]...); ferr != nil {
		return errors.Join(kerr, ferr)
	}
	return nil
}

func (d *fuseDriver) AssembleOverlay(ctx context.Context, lowers []string, upper, work, merged string, readOnly bool) (func() error, error) {
	// First try the kernel overlay driver on top of the FUSE lowerdirs. Modern
	// kernels (~5.11+) allow this in user namespaces. If that fails, fall back
	// to fuse-overlayfs.
	kArgs := buildKernelOverlayArgs(lowers, upper, work, merged, readOnly)
	if err := runCmd(ctx, kArgs[0], kArgs[1:]...); err == nil {
		return func() error {
			return kernelUnmount(context.Background(), merged)
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

// kernelUnmount unmounts mp with umount(2) rather than umount(8).
//
// UMOUNT_NOFOLLOW is the reason: it makes the kernel refuse a symlink at the
// final component atomically, which no check-then-exec can do. umount(8)
// canonicalizes its argument, so a symlink swapped into <dest>/merged after
// validation but before the exec would still be followed, and in kernel mode
// that is a root umount of whatever it points at.
//
// This covers the final component only. A symlinked *parent* -- <dest>/layers
// itself -- resolves during the syscall's own path walk, and checkResolved is
// what rejects that, with the narrower race it documents.
// errSymlinkedMountpoint reports a mountpoint whose final component is a
// symlink. UMOUNT_NOFOLLOW refuses those, and callers use this to tell the
// refusal apart from an ordinary unmount failure.
var errSymlinkedMountpoint = errors.New("refusing to follow a symlink")

func kernelUnmount(ctx context.Context, mp string) error {
	clog.FromContext(ctx).Debugf("umount2: %s (UMOUNT_NOFOLLOW)", mp)
	err := unix.Unmount(mp, unix.UMOUNT_NOFOLLOW)
	if err == nil {
		return nil
	}
	// EINVAL covers both "not a mountpoint" and "target is a symlink", so
	// name the second case rather than leaving the user with "invalid
	// argument". This is for the message only -- the flag above is what
	// provides the guarantee, so an lstat racing it cannot weaken anything.
	if fi, lerr := os.Lstat(mp); lerr == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("umount %s: %w", mp, errSymlinkedMountpoint)
	}
	return fmt.Errorf("umount %s: %w", mp, err)
}

func buildFuseLayerArgs(blob, mp string) []string {
	return []string{"erofsfuse", blob, mp}
}

func buildFusermountUmountArgs(fusermountBin, mp string) []string {
	return []string{fusermountBin, "-u", mp}
}

// escapeOverlayPath quotes a path for use inside an overlayfs mount option
// value. overlayfs splits the option string on "," and lowerdir on ":", and
// treats "\" as an escape (ovl_next_opt and ovl_split_lowerdirs on the way in,
// ovl_unescape for upperdir and workdir), so all three have to be quoted. An
// unescaped ":" is the one that matters: it turns one lowerdir into two, which
// can compose a wrong stack instead of failing.
//
// These paths all derive from the DEST the user named, so they are arbitrary.
// The single-pass replacer is what keeps the backslash rule from re-escaping
// the backslashes the other two rules introduce.
func escapeOverlayPath(p string) string {
	return strings.NewReplacer(`\`, `\\`, `:`, `\:`, `,`, `\,`).Replace(p)
}

// overlayOpts builds the shared "lowerdir=...[,upperdir=...,workdir=...]" that
// both the kernel and fuse-overlayfs option strings start from.
func overlayOpts(lowers []string, upper, work string, readOnly bool) string {
	escaped := make([]string, len(lowers))
	for i, l := range lowers {
		escaped[i] = escapeOverlayPath(l)
	}
	opts := "lowerdir=" + strings.Join(escaped, ":")
	if !readOnly {
		opts += ",upperdir=" + escapeOverlayPath(upper) + ",workdir=" + escapeOverlayPath(work)
	}
	return opts
}

func buildKernelOverlayArgs(lowers []string, upper, work, merged string, readOnly bool) []string {
	opts := overlayOpts(lowers, upper, work, readOnly)
	if readOnly {
		opts += ",ro"
	}
	// merged is its own argv element rather than an option value, so it is
	// passed through unescaped.
	return []string{"mount", "-t", "overlay", "-o", opts, "overlay", merged}
}

func buildFuseOverlayArgs(lowers []string, upper, work, merged string, readOnly bool) []string {
	return []string{"fuse-overlayfs", "-o", overlayOpts(lowers, upper, work, readOnly), merged}
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
