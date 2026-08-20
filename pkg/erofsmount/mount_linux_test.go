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
	"os"
	"path/filepath"
	"slices"
	"testing"

	"chainguard.dev/apko/pkg/build/types"
)

// fakeDriver records what Mount and Unmount ask of a driver instead of
// executing mount(8), so the orchestration -- cleanup ordering, state file
// lifecycle, unmount policy -- can be exercised without root.
type fakeDriver struct {
	name mode

	preflightErr error
	mountErr     map[string]error // mountpoint -> MountLayer failure
	overlayErr   error
	unmountErr   map[string]error // mountpoint -> Unmount failure

	mounted   []string      // MountLayer calls, in order
	overlays  []overlayCall // AssembleOverlay calls, in order
	unmounted []string      // Unmount calls, in order
	closed    []string      // teardown closures invoked, in order
	modes     []mode        // modes the factory was asked for, in order
}

type overlayCall struct {
	lowers              []string
	upper, work, merged string
	readOnly            bool
}

func (f *fakeDriver) Name() mode       { return f.name }
func (f *fakeDriver) Preflight() error { return f.preflightErr }

func (f *fakeDriver) MountLayer(_ context.Context, _, mp string) (func() error, error) {
	if err := f.mountErr[mp]; err != nil {
		return nil, err
	}
	f.mounted = append(f.mounted, mp)
	return func() error {
		f.closed = append(f.closed, mp)
		return nil
	}, nil
}

func (f *fakeDriver) AssembleOverlay(_ context.Context, lowers []string, upper, work, merged string, readOnly bool) (func() error, error) {
	f.overlays = append(f.overlays, overlayCall{
		lowers: slices.Clone(lowers), upper: upper, work: work, merged: merged, readOnly: readOnly,
	})
	if f.overlayErr != nil {
		return nil, f.overlayErr
	}
	return func() error {
		f.closed = append(f.closed, merged)
		return nil
	}, nil
}

func (f *fakeDriver) Unmount(_ context.Context, mp string) error {
	if err := f.unmountErr[mp]; err != nil {
		return err
	}
	if slices.Contains(f.unmounted, mp) {
		// umount(8) exits 32 on a path that is not a mountpoint. Mirroring
		// that keeps a rerun from passing just because the fake is willing to
		// unmount the same path twice.
		return fmt.Errorf("umount %s: not mounted", mp)
	}
	f.unmounted = append(f.unmounted, mp)
	return nil
}

// factory hands the same fake back for any mode, recording which one was
// asked for. Without that record nothing here could catch unmountBlob losing
// its deliberate modeFuse choice, or unmountImage ignoring the mode the state
// file names -- both would break only for real fuse users.
func (f *fakeDriver) factory() driverFactory {
	return func(m mode) (driver, error) {
		f.modes = append(f.modes, m)
		return f, nil
	}
}

func newFakeDriver() *fakeDriver {
	return &fakeDriver{name: modeKernel}
}

// ociDirWithLayers writes a fake OCI layout with n EROFS layers and returns a
// Source for it.
func ociDirWithLayers(t *testing.T, n int) Source {
	t.Helper()
	dir := t.TempDir()
	layers := make([]fakeLayer, 0, n)
	for i := range n {
		l := fakeLayer{body: []byte{byte('a' + i)}}
		if i < n-1 {
			l.role = types.ErofsRoleOverlayLower
		}
		layers = append(layers, l)
	}
	writeFakeOCILayout(t, dir, layers)
	src, err := ParseSource(dir)
	if err != nil {
		t.Fatalf("ParseSource(%s): %v", dir, err)
	}
	return src
}

func TestMountImage_MountOrderAndState(t *testing.T) {
	src := ociDirWithLayers(t, 3)
	dest := t.TempDir()
	f := newFakeDriver()

	if err := mountWith(context.Background(), f.factory(), src, dest, MountOptions{Arch: "amd64"}); err != nil {
		t.Fatalf("mountWith: %v", err)
	}

	wantMounted := []string{
		filepath.Join(dest, "layers", "00"),
		filepath.Join(dest, "layers", "01"),
		filepath.Join(dest, "layers", "02"),
	}
	if !slices.Equal(f.mounted, wantMounted) {
		t.Errorf("mounted:\n got %v\nwant %v", f.mounted, wantMounted)
	}

	if len(f.overlays) != 1 {
		t.Fatalf("got %d AssembleOverlay calls, want 1", len(f.overlays))
	}
	// overlayfs lowerdir is highest-priority first, OCI order is bottom-up.
	wantLowers := []string{wantMounted[2], wantMounted[1], wantMounted[0]}
	if !slices.Equal(f.overlays[0].lowers, wantLowers) {
		t.Errorf("lowers:\n got %v\nwant %v", f.overlays[0].lowers, wantLowers)
	}

	st, err := loadState(dest)
	if err != nil {
		t.Fatalf("loadState: %v", err)
	}
	wantMounts := []string{
		filepath.Join(dest, "merged"),
		wantMounted[2], wantMounted[1], wantMounted[0],
	}
	if !slices.Equal(st.Mounts, wantMounts) {
		t.Errorf("state Mounts:\n got %v\nwant %v", st.Mounts, wantMounts)
	}
	if st.Dest != dest {
		t.Errorf("state Dest: got %q want %q", st.Dest, dest)
	}
	if st.Mode != modeKernel {
		t.Errorf("state Mode: got %q want %q", st.Mode, modeKernel)
	}
}

func TestMountImage_CleansUpInLIFOOnOverlayFailure(t *testing.T) {
	src := ociDirWithLayers(t, 3)
	dest := t.TempDir()
	f := newFakeDriver()
	f.overlayErr = errors.New("overlay boom")

	err := mountWith(context.Background(), f.factory(), src, dest, MountOptions{Arch: "amd64"})
	if err == nil {
		t.Fatal("mountWith succeeded, want overlay failure")
	}

	// Every completed layer mount must come back down, newest first.
	wantClosed := []string{
		filepath.Join(dest, "layers", "02"),
		filepath.Join(dest, "layers", "01"),
		filepath.Join(dest, "layers", "00"),
	}
	if !slices.Equal(f.closed, wantClosed) {
		t.Errorf("torn down:\n got %v\nwant %v", f.closed, wantClosed)
	}

	// A failed mount must not leave a state file claiming success.
	if _, err := os.Stat(statePath(dest)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("state file after failure: stat err = %v, want ErrNotExist", err)
	}
}

func TestMountImage_RefusesExistingStateFile(t *testing.T) {
	src := ociDirWithLayers(t, 2)
	dest := t.TempDir()
	if err := os.WriteFile(statePath(dest), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := newFakeDriver()

	err := mountWith(context.Background(), f.factory(), src, dest, MountOptions{Arch: "amd64"})
	if err == nil {
		t.Fatal("mountWith succeeded, want refusal to clobber an existing mount")
	}
	if len(f.mounted) != 0 {
		t.Errorf("mounted %v, want nothing", f.mounted)
	}
}

func TestMountImage_SingleLayerReadOnlySkipsOverlay(t *testing.T) {
	src := ociDirWithLayers(t, 1)
	dest := t.TempDir()
	f := newFakeDriver()

	// Read-only is the default, so this is the shape an apko-produced
	// single-layer image gets.
	if err := mountWith(context.Background(), f.factory(), src, dest, MountOptions{Arch: "amd64"}); err != nil {
		t.Fatalf("mountWith: %v", err)
	}

	merged := filepath.Join(dest, "merged")
	if !slices.Equal(f.mounted, []string{merged}) {
		t.Errorf("mounted %v, want the layer straight at %s", f.mounted, merged)
	}
	if len(f.overlays) != 0 {
		t.Errorf("got %d AssembleOverlay calls, want none for a single read-only layer", len(f.overlays))
	}
	st, err := loadState(dest)
	if err != nil {
		t.Fatalf("loadState: %v", err)
	}
	if !slices.Equal(st.Mounts, []string{merged}) {
		t.Errorf("state Mounts: got %v want %v", st.Mounts, []string{merged})
	}
}

func TestUnmountImage_OrderAndStateRemoval(t *testing.T) {
	src := ociDirWithLayers(t, 3)
	dest := t.TempDir()
	f := newFakeDriver()
	if err := mountWith(context.Background(), f.factory(), src, dest, MountOptions{Arch: "amd64"}); err != nil {
		t.Fatalf("mountWith: %v", err)
	}
	recorded, err := loadState(dest)
	if err != nil {
		t.Fatalf("loadState: %v", err)
	}

	if err := unmountWith(context.Background(), f.factory(), dest); err != nil {
		t.Fatalf("unmountWith: %v", err)
	}

	// Unmount order is exactly what the state file recorded: merged first,
	// then layers top-down.
	if !slices.Equal(f.unmounted, recorded.Mounts) {
		t.Errorf("unmounted:\n got %v\nwant %v", f.unmounted, recorded.Mounts)
	}
	if _, err := os.Stat(statePath(dest)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("state file after unmount: stat err = %v, want ErrNotExist", err)
	}
	for _, sub := range []string{"merged", "work", "layers"} {
		if _, err := os.Stat(filepath.Join(dest, sub)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s after unmount: stat err = %v, want ErrNotExist", sub, err)
		}
	}
}

func TestUnmount_NoStateFileUnmountsDestItself(t *testing.T) {
	dest := t.TempDir()
	f := newFakeDriver()

	if err := unmountWith(context.Background(), f.factory(), dest); err != nil {
		t.Fatalf("unmountWith: %v", err)
	}
	if !slices.Equal(f.unmounted, []string{dest}) {
		t.Errorf("unmounted %v, want the blob mountpoint %s", f.unmounted, dest)
	}
	// A blob records no mode, so the fall-back deliberately picks fuse: its
	// Unmount is the kernel-then-fusermount chain that covers either.
	if !slices.Equal(f.modes, []mode{modeFuse}) {
		t.Errorf("driver modes %v, want the blob fall-back to ask for %q", f.modes, modeFuse)
	}
}

// The mode is requested twice over a mount's life -- from the flag on the way
// up, from the state file on the way down -- and neither was observed before.
func TestMountUnmount_DriverModeFollowsFlagThenState(t *testing.T) {
	src := ociDirWithLayers(t, 2)
	dest := t.TempDir()
	f := newFakeDriver()

	if err := mountWith(context.Background(), f.factory(), src, dest, MountOptions{Arch: "amd64", Mode: "fuse"}); err != nil {
		t.Fatalf("mountWith: %v", err)
	}
	if !slices.Equal(f.modes, []mode{modeFuse}) {
		t.Errorf("driver modes after mount: got %v want [%q]", f.modes, modeFuse)
	}

	// The fake reports itself as kernel regardless, so that is what the state
	// file records and what unmount must ask for.
	if err := unmountWith(context.Background(), f.factory(), dest); err != nil {
		t.Fatalf("unmountWith: %v", err)
	}
	if want := []mode{modeFuse, modeKernel}; !slices.Equal(f.modes, want) {
		t.Errorf("driver modes overall: got %v want %v", f.modes, want)
	}
}

// Preflight is what reports a missing mount(8) or a non-root kernel mount, so
// nothing may happen before it has passed.
func TestMountImage_PreflightFailureStopsBeforeAnything(t *testing.T) {
	src := ociDirWithLayers(t, 2)
	dest := t.TempDir()
	f := newFakeDriver()
	f.preflightErr = errors.New("mount(8) not found")

	err := mountWith(context.Background(), f.factory(), src, dest, MountOptions{Arch: "amd64"})
	if err == nil {
		t.Fatal("mountWith succeeded despite a Preflight failure")
	}
	if len(f.mounted) != 0 || len(f.overlays) != 0 {
		t.Errorf("mounted %v / overlays %d, want nothing", f.mounted, len(f.overlays))
	}
	// Including the dest claim: a failed mount must leave no state file.
	if _, err := os.Stat(statePath(dest)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("state file after a Preflight failure: stat err = %v, want ErrNotExist", err)
	}
}

func TestUnmount_PlantedStateFileNeverReachesUmount(t *testing.T) {
	dest := t.TempDir()
	victim := t.TempDir()
	planted(t, dest, dest, []string{victim})

	f := newFakeDriver()
	err := unmountWith(context.Background(), f.factory(), dest)
	if err == nil {
		t.Fatal("unmountWith succeeded on a state file naming a path outside dest")
	}
	// The point of the check: nothing is handed to umount at all, rather than
	// the escape being noticed after the fact.
	if len(f.unmounted) != 0 {
		t.Errorf("unmounted %v; a planted state file must not reach umount", f.unmounted)
	}
	if _, err := os.Stat(victim); err != nil {
		t.Errorf("victim dir disturbed: %v", err)
	}
}

// The whitelist in validate constrains the path string; this covers the other
// half, a name that passes it but resolves somewhere else. umount(8)
// canonicalizes its argument, so following the symlink would take the victim
// down instead.
func TestUnmountImage_SymlinkedMountpointNeverReachesUmount(t *testing.T) {
	src := ociDirWithLayers(t, 3)
	dest := t.TempDir()
	f := newFakeDriver()
	if err := mountWith(context.Background(), f.factory(), src, dest, MountOptions{Arch: "amd64"}); err != nil {
		t.Fatalf("mountWith: %v", err)
	}

	// Stand in for an attacker with write access to dest swapping merged --
	// the first entry in the state file -- for a link elsewhere.
	victim := t.TempDir()
	merged := filepath.Join(dest, "merged")
	if err := os.Remove(merged); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, merged); err != nil {
		t.Fatal(err)
	}

	if err := unmountWith(context.Background(), f.factory(), dest); err == nil {
		t.Fatal("unmountWith succeeded on a mountpoint that resolves outside dest")
	}
	if len(f.unmounted) != 0 {
		t.Errorf("unmounted %v; a redirected mountpoint must not reach umount", f.unmounted)
	}
	if _, err := os.Stat(victim); err != nil {
		t.Errorf("victim dir disturbed: %v", err)
	}
}

func TestUnmountImage_PartialFailureIsResumable(t *testing.T) {
	src := ociDirWithLayers(t, 3)
	dest := t.TempDir()
	f := newFakeDriver()
	if err := mountWith(context.Background(), f.factory(), src, dest, MountOptions{Arch: "amd64"}); err != nil {
		t.Fatalf("mountWith: %v", err)
	}

	merged := filepath.Join(dest, "merged")
	top := filepath.Join(dest, "layers", "02")
	busy := filepath.Join(dest, "layers", "01")
	base := filepath.Join(dest, "layers", "00")

	// Something still has layers/01 open.
	f.unmountErr = map[string]error{busy: errors.New("target is busy")}
	if err := unmountWith(context.Background(), f.factory(), dest); err == nil {
		t.Fatal("unmountWith succeeded with a busy mount")
	}
	if want := []string{merged, top}; !slices.Equal(f.unmounted, want) {
		t.Errorf("unmounted before the failure:\n got %v\nwant %v", f.unmounted, want)
	}

	// The state file must now describe only what is still up, or the rerun
	// below starts at merged -- already gone -- and dies there.
	st, err := loadState(dest)
	if err != nil {
		t.Fatalf("loadState after partial unmount: %v", err)
	}
	if want := []string{busy, base}; !slices.Equal(st.Mounts, want) {
		t.Fatalf("state Mounts after partial unmount:\n got %v\nwant %v", st.Mounts, want)
	}

	// Whatever held it open lets go; the rerun finishes the job.
	f.unmountErr = nil
	if err := unmountWith(context.Background(), f.factory(), dest); err != nil {
		t.Fatalf("rerun after the busy mount cleared: %v", err)
	}
	if want := []string{merged, top, busy, base}; !slices.Equal(f.unmounted, want) {
		t.Errorf("unmounted overall:\n got %v\nwant %v", f.unmounted, want)
	}
	if _, err := os.Stat(statePath(dest)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("state file after the rerun: stat err = %v, want ErrNotExist", err)
	}
}

func TestMountImage_ReadOnlyByDefault(t *testing.T) {
	src := ociDirWithLayers(t, 2)
	dest := t.TempDir()
	f := newFakeDriver()

	if err := mountWith(context.Background(), f.factory(), src, dest, MountOptions{Arch: "amd64"}); err != nil {
		t.Fatalf("mountWith: %v", err)
	}

	if len(f.overlays) != 1 {
		t.Fatalf("got %d AssembleOverlay calls, want 1", len(f.overlays))
	}
	if !f.overlays[0].readOnly {
		t.Error("overlay assembled read-write; the default must be read-only")
	}
	// No upperdir means nothing to create and nothing to lose on umount.
	for _, sub := range []string{"upper", "work"} {
		if _, err := os.Stat(filepath.Join(dest, sub)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s exists for a read-only mount: stat err = %v", sub, err)
		}
	}
	st, err := loadState(dest)
	if err != nil {
		t.Fatalf("loadState: %v", err)
	}
	if st.Writable {
		t.Error("state records a writable mount")
	}
}

func TestMountImage_WritableKeepsUpperOnUnmount(t *testing.T) {
	src := ociDirWithLayers(t, 2)
	dest := t.TempDir()
	f := newFakeDriver()

	if err := mountWith(context.Background(), f.factory(), src, dest, MountOptions{Arch: "amd64", Writable: true}); err != nil {
		t.Fatalf("mountWith: %v", err)
	}
	if len(f.overlays) != 1 {
		t.Fatalf("got %d AssembleOverlay calls, want 1", len(f.overlays))
	}
	if f.overlays[0].readOnly {
		t.Error("overlay assembled read-only despite Writable")
	}
	upper := filepath.Join(dest, "upper")
	for _, sub := range []string{"upper", "work"} {
		if _, err := os.Stat(filepath.Join(dest, sub)); err != nil {
			t.Errorf("%s missing for a writable mount: %v", sub, err)
		}
	}

	// Something written through the mount lands in upper.
	written := filepath.Join(upper, "written-through-the-mount")
	if err := os.WriteFile(written, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := unmountWith(context.Background(), f.factory(), dest); err != nil {
		t.Fatalf("unmountWith: %v", err)
	}

	// The whole point: umount must not silently discard it.
	if got, err := os.ReadFile(written); err != nil {
		t.Errorf("upper contents discarded by umount: %v", err)
	} else if string(got) != "keep me" {
		t.Errorf("upper contents changed: got %q", got)
	}
	// Everything else still goes.
	for _, sub := range []string{"merged", "work", "layers"} {
		if _, err := os.Stat(filepath.Join(dest, sub)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s after unmount: stat err = %v, want ErrNotExist", sub, err)
		}
	}
}

// An upper that was never written to is not worth keeping, and leaving the
// empty directory would make the next --rw mount at this dest refuse.
func TestUnmountImage_RemovesAnUnwrittenUpper(t *testing.T) {
	src := ociDirWithLayers(t, 2)
	dest := t.TempDir()
	f := newFakeDriver()

	if err := mountWith(context.Background(), f.factory(), src, dest, MountOptions{Arch: "amd64", Writable: true}); err != nil {
		t.Fatalf("mountWith: %v", err)
	}
	if err := unmountWith(context.Background(), f.factory(), dest); err != nil {
		t.Fatalf("unmountWith: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dest, "upper")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("empty upper left behind: stat err = %v, want ErrNotExist", err)
	}
	// And so the dest is reusable.
	if err := mountWith(context.Background(), f.factory(), src, dest, MountOptions{Arch: "amd64", Writable: true}); err != nil {
		t.Errorf("second --rw mount at the same dest: %v", err)
	}
}

// The mount-side half of the symlink problem: MkdirAll accepts a link to an
// existing directory, so without a check the layer would be mounted over
// whatever it points at -- and Unmount would then refuse to take it down.
func TestMountImage_RefusesASymlinkedMountpoint(t *testing.T) {
	src := ociDirWithLayers(t, 1)
	dest := t.TempDir()
	victim := t.TempDir()
	if err := os.Symlink(victim, filepath.Join(dest, "merged")); err != nil {
		t.Fatal(err)
	}

	f := newFakeDriver()
	err := mountWith(context.Background(), f.factory(), src, dest, MountOptions{Arch: "amd64"})
	if err == nil {
		t.Fatal("mountWith succeeded with merged symlinked out of dest")
	}
	if len(f.mounted) != 0 {
		t.Errorf("mounted %v, want nothing", f.mounted)
	}
}

// The other half of keeping a written-through upper: it must not be silently
// stacked under a second mount, whose lowers may be a different image
// entirely.
func TestMountImage_RefusesANonEmptyUpper(t *testing.T) {
	src := ociDirWithLayers(t, 2)
	dest := t.TempDir()
	upper := filepath.Join(dest, "upper")
	if err := os.Mkdir(upper, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(upper, "from-an-earlier-mount"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	f := newFakeDriver()
	err := mountWith(context.Background(), f.factory(), src, dest, MountOptions{Arch: "amd64", Writable: true})
	if err == nil {
		t.Fatal("mountWith succeeded on top of a non-empty upper")
	}
	if len(f.mounted) != 0 {
		t.Errorf("mounted %v, want nothing", f.mounted)
	}

	// Read-only never touches upper, so it is still allowed.
	if err := mountWith(context.Background(), f.factory(), src, dest, MountOptions{Arch: "amd64"}); err != nil {
		t.Errorf("read-only mount refused because of a leftover upper: %v", err)
	}
}
