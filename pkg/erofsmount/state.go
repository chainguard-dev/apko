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
	"time"
)

// Mode selects how mounts are performed. ModeAuto is resolved to ModeKernel or
// ModeFuse before being recorded in MountState.
type Mode string

const (
	ModeAuto   Mode = "auto"
	ModeKernel Mode = "kernel"
	ModeFuse   Mode = "fuse"
)

// Options is the shared option bag used by Mount and Ls. Only Arch is
// meaningful for Ls; Mode and ReadOnly only affect Mount.
type Options struct {
	// Mode selects ModeKernel, ModeFuse, or ModeAuto. Zero value is
	// treated as ModeAuto.
	Mode Mode
	// Arch picks a manifest from a multi-arch OCI index. "" or "host"
	// means runtime.GOARCH.
	Arch string
	// ReadOnly, when true, skips upper/work overlay dirs and produces a
	// pure read-only overlay during Mount.
	ReadOnly bool
}

// StateSchemaVersion is the current MountState JSON schema version.
const StateSchemaVersion = 1

// stateFileName is written inside <dest> for image mounts (multi-layer overlay
// or single-layer wrapped in an OCI layout). It is *not* written for raw blob
// mounts: there is no enclosing directory for them.
const stateFileName = ".apko-erofs-mount.json"

// MountState describes a completed mount produced by Mount. The file
// authoritatively records what was mounted so that Unmount can tear it down
// without re-deriving the layout from the source.
type MountState struct {
	SchemaVersion int       `json:"schemaVersion"`
	Mode          Mode      `json:"mode"`    // resolved mode (kernel|fuse), never "auto"
	Source        string    `json:"source"`  // the original `spec` argument
	Dest          string    `json:"dest"`    // absolute path of the mount target
	Created       time.Time `json:"created"` // wall-clock timestamp at mount completion
	// Mounts lists every mountpoint produced by Mount in unmount order
	// (LIFO): the first element is unmounted first. For an image mount this
	// is [<dest>/merged, <dest>/layers/NN, ..., <dest>/layers/00].
	Mounts []string `json:"mounts"`
}

// StatePath returns the location of the state file inside dest.
func StatePath(dest string) string {
	return filepath.Join(dest, stateFileName)
}

// WriteState writes s atomically to StatePath(dest). The file is written via
// CreateTemp+Rename in the same directory so a partial write can never be
// observed.
func WriteState(dest string, s *MountState) error {
	path := StatePath(dest)
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

// LoadState reads StatePath(dest). If the file does not exist, the returned
// error wraps fs.ErrNotExist so callers can use errors.Is.
func LoadState(dest string) (*MountState, error) {
	path := StatePath(dest)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("no mount state at %s: %w", path, err)
		}
		return nil, fmt.Errorf("read state %s: %w", path, err)
	}
	var s MountState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse state %s: %w", path, err)
	}
	if s.SchemaVersion != StateSchemaVersion {
		return nil, fmt.Errorf("state %s: unsupported schemaVersion %d (want %d)", path, s.SchemaVersion, StateSchemaVersion)
	}
	return &s, nil
}

// RemoveState deletes StatePath(dest). It is a no-op if the file is already
// absent.
func RemoveState(dest string) error {
	err := os.Remove(StatePath(dest))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
