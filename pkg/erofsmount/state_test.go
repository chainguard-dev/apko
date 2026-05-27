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
	"testing"
	"time"
)

func TestStateRoundTrip(t *testing.T) {
	dest := t.TempDir()
	in := &MountState{
		SchemaVersion: StateSchemaVersion,
		Mode:          ModeKernel,
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
	if err := WriteState(dest, in); err != nil {
		t.Fatalf("WriteState: %v", err)
	}
	if _, err := os.Stat(StatePath(dest)); err != nil {
		t.Fatalf("state file missing: %v", err)
	}

	out, err := LoadState(dest)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
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

	if err := RemoveState(dest); err != nil {
		t.Fatalf("RemoveState: %v", err)
	}
	if _, err := os.Stat(StatePath(dest)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("state still present after remove: err=%v", err)
	}
	// Idempotent remove.
	if err := RemoveState(dest); err != nil {
		t.Fatalf("RemoveState (idempotent): %v", err)
	}
}

func TestLoadStateMissing(t *testing.T) {
	dest := t.TempDir()
	_, err := LoadState(dest)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("error %v should wrap fs.ErrNotExist", err)
	}
}

func TestLoadStateWrongSchema(t *testing.T) {
	dest := t.TempDir()
	if err := os.WriteFile(StatePath(dest), []byte(`{"schemaVersion":99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(dest); err == nil {
		t.Fatal("expected schema version error")
	}
}
