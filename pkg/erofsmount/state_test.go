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

package erofsmount

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestStateRoundTrip(t *testing.T) {
	dest := t.TempDir()
	in := &mountState{
		SchemaVersion: stateSchemaVersion,
		Mode:          modeKernel,
		Source:        "oci-dir:./out:latest",
		Dest:          dest,
		Created:       time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC),
		Mounts: []string{
			filepath.Join(dest, "merged"),
			filepath.Join(dest, "layers", "02"),
			filepath.Join(dest, "layers", "01"),
			filepath.Join(dest, "layers", "00"),
		},
	}
	if err := writeState(dest, in); err != nil {
		t.Fatalf("writeState: %v", err)
	}
	if _, err := os.Stat(statePath(dest)); err != nil {
		t.Fatalf("state file missing: %v", err)
	}

	out, err := loadState(dest)
	if err != nil {
		t.Fatalf("loadState: %v", err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("roundtrip mismatch:\n  in=%+v\n out=%+v", in, out)
	}

	// No leftover tempfile from the atomic write.
	entries, err := os.ReadDir(dest)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if len(name) > len(".apko-erofs-mount-") && name[:len(".apko-erofs-mount-")] == ".apko-erofs-mount-" {
			t.Errorf("stray tempfile left behind: %s", name)
		}
	}

	if err := removeState(dest); err != nil {
		t.Fatalf("removeState: %v", err)
	}
	if _, err := os.Stat(statePath(dest)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("state still present after remove: err=%v", err)
	}
	// Idempotent remove.
	if err := removeState(dest); err != nil {
		t.Fatalf("removeState (idempotent): %v", err)
	}
}

func TestLoadStateMissing(t *testing.T) {
	dest := t.TempDir()
	_, err := loadState(dest)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("error %v should wrap fs.ErrNotExist", err)
	}
}

func TestLoadStateWrongSchema(t *testing.T) {
	dest := t.TempDir()
	if err := os.WriteFile(statePath(dest), []byte(`{"schemaVersion":99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadState(dest); err == nil {
		t.Fatal("expected schema version error")
	}
}

// planted writes a state file with the given mounts directly, as an attacker
// with write access to dest would.
func planted(t *testing.T, dest string, recordedDest string, mounts []string) {
	t.Helper()
	if err := writeState(dest, &mountState{
		SchemaVersion: stateSchemaVersion,
		Mode:          modeKernel,
		Dest:          recordedDest,
		Created:       time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC),
		Mounts:        mounts,
	}); err != nil {
		t.Fatalf("writeState: %v", err)
	}
}

func TestLoadStateRejectsMountsOutsideDest(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mount func(dest string) string
	}{
		{"absolute elsewhere", func(string) string { return "/home" }},
		{"parent of dest", filepath.Dir},
		{"traversal through dest", func(dest string) string { return filepath.Join(dest, "..", "..", "etc") }},
		{"traversal through layers", func(dest string) string { return filepath.Join(dest, "layers", "..", "..", "home") }},
		{"relative", func(string) string { return "merged" }},
		{"dest itself", func(dest string) string { return dest }},
		{"unexpected subdir", func(dest string) string { return filepath.Join(dest, "upper") }},
		{"layer name not numeric", func(dest string) string { return filepath.Join(dest, "layers", "evil") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dest := t.TempDir()
			planted(t, dest, dest, []string{tc.mount(dest)})
			if _, err := loadState(dest); err == nil {
				t.Fatalf("loadState accepted mount %q", tc.mount(dest))
			}
		})
	}
}

func TestLoadStateRejectsDestMismatch(t *testing.T) {
	dest := t.TempDir()
	// The recorded dest is a directory the attacker does control, while the
	// mount path is inside the dest being unmounted -- so a containment-only
	// check would pass this.
	planted(t, dest, t.TempDir(), []string{filepath.Join(dest, "merged")})
	if _, err := loadState(dest); err == nil {
		t.Fatal("loadState accepted a state file recording a different dest")
	}
}

func TestLoadStateRejectsNoMounts(t *testing.T) {
	dest := t.TempDir()
	planted(t, dest, dest, nil)
	if _, err := loadState(dest); err == nil {
		t.Fatal("loadState accepted a state file with no mounts")
	}
}

// resolved is checkResolved with dest resolved the way unmountImage does it.
func resolved(t *testing.T, dest, mp string) error {
	t.Helper()
	realDest, err := filepath.EvalSymlinks(dest)
	if err != nil {
		t.Fatalf("EvalSymlinks(%s): %v", dest, err)
	}
	return checkResolved(dest, realDest, mp)
}

func TestCheckResolvedAcceptsRealDirectories(t *testing.T) {
	dest := t.TempDir()
	for _, sub := range []string{"merged", "layers/00"} {
		mp := filepath.Join(dest, sub)
		if err := os.MkdirAll(mp, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := resolved(t, dest, mp); err != nil {
			t.Errorf("checkResolved rejected the real directory %s: %v", mp, err)
		}
	}
}

// The name passes validate -- it is literally <dest>/merged -- but umount(8)
// canonicalizes, so following it would take down the victim instead.
func TestCheckResolvedRejectsSymlinkedMountpoint(t *testing.T) {
	dest := t.TempDir()
	victim := t.TempDir()
	mp := filepath.Join(dest, "merged")
	if err := os.Symlink(victim, mp); err != nil {
		t.Fatal(err)
	}
	if err := resolved(t, dest, mp); err == nil {
		t.Fatalf("checkResolved accepted %s -> %s", mp, victim)
	}
}

// A symlink higher up the recorded path is the same attack one level out.
func TestCheckResolvedRejectsSymlinkedParent(t *testing.T) {
	dest := t.TempDir()
	victim := t.TempDir()
	if err := os.Mkdir(filepath.Join(victim, "00"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(dest, "layers")); err != nil {
		t.Fatal(err)
	}
	mp := filepath.Join(dest, "layers", "00")
	if err := resolved(t, dest, mp); err == nil {
		t.Fatalf("checkResolved accepted %s through a symlinked parent", mp)
	}
}

// A dest that is itself reached through a symlink -- /var/run/... and the like
// -- is legitimate, and the check must not reject it just because dest and its
// resolution differ.
func TestCheckResolvedToleratesSymlinkedDest(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(real, "merged"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := resolved(t, link, filepath.Join(link, "merged")); err != nil {
		t.Errorf("checkResolved rejected a dest reached through a symlink: %v", err)
	}
}

func TestCheckResolvedRejectsMissingPath(t *testing.T) {
	dest := t.TempDir()
	if err := resolved(t, dest, filepath.Join(dest, "merged")); err == nil {
		t.Fatal("checkResolved accepted a path that does not exist")
	}
}

// A repeat is inside dest, so it escapes nothing -- but the second umount of
// it fails on a path that is no longer a mountpoint, wedging the teardown at
// an entry that is already done.
func TestLoadStateRejectsDuplicateMounts(t *testing.T) {
	dest := t.TempDir()
	merged := filepath.Join(dest, "merged")
	planted(t, dest, dest, []string{merged, merged})
	if _, err := loadState(dest); err == nil {
		t.Fatal("loadState accepted a mount listed twice")
	}
}

// claimState leaves an empty file behind if the mount dies before writeState;
// say so rather than reporting a JSON syntax error.
func TestLoadStateRejectsAnEmptyFile(t *testing.T) {
	dest := t.TempDir()
	if err := claimState(dest); err != nil {
		t.Fatal(err)
	}
	_, err := loadState(dest)
	if err == nil {
		t.Fatal("loadState accepted an empty state file")
	}
	if !strings.Contains(err.Error(), "interrupted") {
		t.Errorf("error %q does not explain the empty file", err)
	}
}

func TestClaimStateIsExclusive(t *testing.T) {
	dest := t.TempDir()
	if err := claimState(dest); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if err := claimState(dest); err == nil {
		t.Fatal("second claim succeeded; the first must win the dest")
	}
	// And the claim is what a later writeState replaces.
	if err := removeState(dest); err != nil {
		t.Fatal(err)
	}
	if err := claimState(dest); err != nil {
		t.Fatalf("claim after release: %v", err)
	}
}

func TestLoadStateAcceptsWhatMountWrites(t *testing.T) {
	dest := t.TempDir()
	planted(t, dest, dest, []string{
		filepath.Join(dest, "merged"),
		filepath.Join(dest, "layers", "99"),
		filepath.Join(dest, "layers", "000"),
	})
	if _, err := loadState(dest); err != nil {
		t.Fatalf("loadState rejected a legitimate layout: %v", err)
	}
}
