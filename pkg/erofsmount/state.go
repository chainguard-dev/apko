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
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// mode selects how mounts are performed. modeAuto is resolved to modeKernel or
// modeFuse before being recorded in mountState.
type mode string

const (
	modeAuto   mode = "auto"
	modeKernel mode = "kernel"
	modeFuse   mode = "fuse"
)

// MountOptions is the option bag accepted by Mount. It is the only exported
// part of the mount plane's configuration: mode is an internal type, so the
// Mode field is a plain string converted on the way in.
type MountOptions struct {
	// Mode selects "kernel", "fuse", or "auto". Zero value is treated as
	// "auto" (kernel if euid 0, else fuse).
	Mode string
	// Arch picks a manifest from a multi-arch OCI index. "" or "host"
	// means runtime.GOARCH.
	Arch string
	// Writable, when true, gives the mount an overlayfs upperdir so it can
	// be written through. The zero value is read-only, which is what
	// inspecting an image wants; writes are opt-in because a writable
	// mount accumulates state that has nowhere to go when it comes down.
	Writable bool
}

// stateSchemaVersion is the current mountState JSON schema version.
const stateSchemaVersion = 1

// stateFileName is written inside <dest> for image mounts (multi-layer overlay
// or single-layer wrapped in an OCI layout). It is *not* written for raw blob
// mounts: there is no enclosing directory for them.
const stateFileName = ".apko-erofs-mount.json"

// mountState describes a completed mount produced by Mount. The file
// authoritatively records what was mounted so that Unmount can tear it down
// without re-deriving the layout from the source.
type mountState struct {
	SchemaVersion int       `json:"schemaVersion"`
	Mode          mode      `json:"mode"`    // resolved mode (kernel|fuse), never "auto"
	Source        string    `json:"source"`  // the original `spec` argument
	Dest          string    `json:"dest"`    // absolute path of the mount target
	Created       time.Time `json:"created"` // wall-clock timestamp at mount completion
	// Writable records whether the mount has an upperdir, so Unmount knows
	// whether <dest>/upper holds anything worth keeping.
	Writable bool `json:"writable"`
	// Mounts lists every mountpoint produced by Mount in unmount order
	// (LIFO): the first element is unmounted first. For an image mount this
	// is [<dest>/merged, <dest>/layers/NN, ..., <dest>/layers/00].
	Mounts []string `json:"mounts"`
}

// statePath returns the location of the state file inside dest.
func statePath(dest string) string {
	return filepath.Join(dest, stateFileName)
}

// writeState writes s atomically to statePath(dest). The file is written via
// CreateTemp+Rename in the same directory so a partial write can never be
// observed.
func writeState(dest string, s *mountState) error {
	path := statePath(dest)
	tmp, err := os.CreateTemp(filepath.Dir(path), ".apko-erofs-mount-*.json")
	if err != nil {
		return fmt.Errorf("create state tmpfile: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		// Best-effort cleanup if Rename never happened.
		_ = os.Remove(tmpName)
	}()
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(s); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("encode state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close state: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename state into place: %w", err)
	}
	return nil
}

// loadState reads statePath(dest). If the file does not exist, the returned
// error wraps fs.ErrNotExist so callers can use errors.Is.
func loadState(dest string) (*mountState, error) {
	path := statePath(dest)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("no mount state at %s: %w", path, err)
		}
		return nil, fmt.Errorf("read state %s: %w", path, err)
	}
	var s mountState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse state %s: %w", path, err)
	}
	if s.SchemaVersion != stateSchemaVersion {
		return nil, fmt.Errorf("state %s: unsupported schemaVersion %d (want %d)", path, s.SchemaVersion, stateSchemaVersion)
	}
	if err := s.validate(dest); err != nil {
		return nil, fmt.Errorf("state %s: %w", path, err)
	}
	return &s, nil
}

// mountRelPattern matches the per-layer mountpoints Mount creates, relative to
// dest. The only other one it creates is "merged".
var mountRelPattern = regexp.MustCompile(`^layers/[0-9]{2,}$`)

// validate checks a state file before any path it names is handed to umount,
// which in kernel mode runs as root. The file lives inside dest, so anyone who
// can write there controls its contents; unvalidated, a planted file naming
// /home would have root unmount /home.
//
// Rather than only checking containment, this requires each entry to be one of
// the paths Mount actually creates. Nothing legitimate is rejected: mounts are
// made at <dest>/merged and <dest>/layers/NN and nowhere else.
func (s *mountState) validate(dest string) error {
	if s.Dest != dest {
		return fmt.Errorf("records dest %q but was read from %q", s.Dest, dest)
	}
	if len(s.Mounts) == 0 {
		return errors.New("records no mounts")
	}
	for _, mp := range s.Mounts {
		if !filepath.IsAbs(mp) {
			return fmt.Errorf("mount %q is not an absolute path", mp)
		}
		rel, err := filepath.Rel(dest, filepath.Clean(mp))
		if err != nil {
			return fmt.Errorf("mount %q is not under %s: %w", mp, dest, err)
		}
		if rel != "merged" && !mountRelPattern.MatchString(rel) {
			return fmt.Errorf("mount %q is not a path a mount creates under %s (merged, layers/NN)", mp, dest)
		}
	}
	return nil
}

// checkResolved verifies that mp still resolves to the path its name claims.
//
// validate constrains the path *string* to one that Mount creates, which says
// nothing about where that path actually leads: a symlink planted at
// <dest>/merged would redirect a root umount without the name ever looking
// wrong. realDest is dest with its own symlinks resolved, so a legitimately
// symlinked dest (say one under /var/run) still works and only the components
// below it have to be real.
//
// The final component is not this check's job -- kernelUnmount passes
// UMOUNT_NOFOLLOW, which refuses it in the same syscall that unmounts, with no
// window at all. What is left to this is a symlinked *parent*, <dest>/layers
// itself, which the kernel resolves during its own path walk. There the check
// and the umount are separate steps, so someone who can write inside dest can
// still swap a directory for a symlink in between; that residual is why the
// docs say to use a dest only you can write to.
func checkResolved(dest, realDest, mp string) error {
	rel, err := filepath.Rel(dest, mp)
	if err != nil {
		return fmt.Errorf("relative to %s: %w", dest, err)
	}
	resolved, err := filepath.EvalSymlinks(mp)
	if err != nil {
		return fmt.Errorf("resolve: %w", err)
	}
	if want := filepath.Join(realDest, rel); resolved != want {
		return fmt.Errorf("resolves to %q, not %q; a path component is a symlink", resolved, want)
	}
	return nil
}

// removeState deletes statePath(dest). It is a no-op if the file is already
// absent.
func removeState(dest string) error {
	err := os.Remove(statePath(dest))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
