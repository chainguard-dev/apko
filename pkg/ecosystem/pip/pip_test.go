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

package pip

import (
	"testing"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/ecosystem"
)

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
