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
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFormatMode(t *testing.T) {
	cases := []struct {
		mode fs.FileMode
		want string
	}{
		{fs.ModeDir | 0o755, "drwxr-xr-x"},
		{0o644, "-rw-r--r--"},
		{fs.ModeSymlink | 0o777, "lrwxrwxrwx"},
		{0o600, "-rw-------"},
		{fs.ModeNamedPipe | 0o644, "prw-r--r--"},
	}
	for _, c := range cases {
		got := formatMode(c.mode)
		if got != c.want {
			t.Errorf("formatMode(%v): got %q, want %q", c.mode, got, c.want)
		}
	}
}

func TestWalkAndPrint(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bin", "sh"), []byte("hi"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/bin/busybox", filepath.Join(root, "bin", "ls")); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := walkAndPrint(context.Background(), root, &buf); err != nil {
		t.Fatalf("walkAndPrint: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "bin/sh") {
		t.Errorf("output missing bin/sh:\n%s", out)
	}
	if !strings.Contains(out, "bin/ls -> /bin/busybox") {
		t.Errorf("symlink target missing:\n%s", out)
	}
	// Root itself must not be listed: every emitted relpath must start with
	// a known top-level child (bin/...). Strip any " -> target" suffix.
	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		fields := strings.Fields(line)
		rel := fields[len(fields)-1]
		if left, _, ok := strings.Cut(line, " -> "); ok {
			before := strings.Fields(left)
			rel = before[len(before)-1]
		}
		if strings.HasPrefix(rel, "/") || rel == "." || rel == "" {
			t.Errorf("relpath %q looks wrong in: %s", rel, line)
		}
	}
}
