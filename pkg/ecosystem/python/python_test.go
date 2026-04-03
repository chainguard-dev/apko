// Copyright 2024 Chainguard, Inc.
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

package python

import (
	"testing"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/ecosystem"
)

func TestCreateVenv(t *testing.T) {
	fs := apkfs.NewMemFS()
	if err := fs.MkdirAll("usr/bin", 0755); err != nil {
		t.Fatal(err)
	}

	err := createVenv(fs, "app/venv", "3.12")
	if err != nil {
		t.Fatalf("createVenv() error: %v", err)
	}

	// Check pyvenv.cfg
	data, err := fs.ReadFile("app/venv/pyvenv.cfg")
	if err != nil {
		t.Fatalf("reading pyvenv.cfg: %v", err)
	}
	cfg := string(data)
	if !contains(cfg, "home = /usr/bin") {
		t.Errorf("pyvenv.cfg missing home, got: %q", cfg)
	}
	if !contains(cfg, "version = 3.12") {
		t.Errorf("pyvenv.cfg missing version, got: %q", cfg)
	}

	// Check directories exist
	for _, dir := range []string{
		"app/venv/bin",
		"app/venv/include",
		"app/venv/lib/python3.12/site-packages",
	} {
		if _, err := fs.Stat(dir); err != nil {
			t.Errorf("directory %s should exist: %v", dir, err)
		}
	}

	// Check symlinks
	for _, name := range []string{"python", "python3", "python3.12"} {
		target, err := fs.Readlink("app/venv/bin/" + name)
		if err != nil {
			t.Errorf("symlink %s should exist: %v", name, err)
			continue
		}
		if target != "/usr/bin/python3.12" {
			t.Errorf("symlink %s = %q, want %q", name, target, "/usr/bin/python3.12")
		}
	}
}


func TestInstallerRegistration(t *testing.T) {
	inst, ok := ecosystem.Get("python")
	if !ok {
		t.Fatal("python installer not registered")
	}
	if inst.Name() != "python" {
		t.Errorf("Name() = %q, want %q", inst.Name(), "python")
	}
}

func TestDetectPythonVersion(t *testing.T) {
	fs := apkfs.NewMemFS()

	// No python installed
	if v := detectPythonVersion(fs); v != "" {
		t.Errorf("detectPythonVersion() = %q on empty fs, want empty", v)
	}

	// Create python directory
	if err := fs.MkdirAll("usr/lib/python3.12/site-packages", 0755); err != nil {
		t.Fatal(err)
	}

	v := detectPythonVersion(fs)
	if v != "3.12" {
		t.Errorf("detectPythonVersion() = %q, want %q", v, "3.12")
	}
}

func TestDetectPythonVersionMultiple(t *testing.T) {
	fs := apkfs.NewMemFS()

	// Create multiple python versions - should return whichever is found first
	if err := fs.MkdirAll("usr/lib/python3.11/site-packages", 0755); err != nil {
		t.Fatal(err)
	}
	if err := fs.MkdirAll("usr/lib/python3.12/site-packages", 0755); err != nil {
		t.Fatal(err)
	}

	v := detectPythonVersion(fs)
	if v != "3.11" && v != "3.12" {
		t.Errorf("detectPythonVersion() = %q, want 3.11 or 3.12", v)
	}
}
