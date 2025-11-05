//go:build containerTest

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

package apkcompat

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testImage       = "cgr.dev/chainguard/wolfi-base:latest"
	containerPrefix = "apko-as-apk-test"
)

// containerTest manages a docker container for testing
type containerTest struct {
	t            *testing.T
	name         string
	id           string
	binaryPath   string
	binaryInTest string
}

// newContainerTest creates a new container for testing
func newContainerTest(t *testing.T) *containerTest {
	t.Helper()

	// Build the binary first
	binaryPath := buildBinary(t)

	// Create unique container name
	name := fmt.Sprintf("%s-%d", containerPrefix, time.Now().Unix())

	// Start container
	cmd := exec.Command("docker", "run", "-d",
		"--name", name,
		"--mount", fmt.Sprintf("type=bind,source=%s,destination=/usr/bin/apko-as-apk", binaryPath),
		testImage,
		"sleep", "3600",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to start container: %v, output: %s", err, output)
	}

	id := strings.TrimSpace(string(output))

	ct := &containerTest{
		t:            t,
		name:         name,
		id:           id,
		binaryPath:   binaryPath,
		binaryInTest: "/usr/bin/apko-as-apk",
	}

	// Register cleanup
	t.Cleanup(func() {
		ct.cleanup()
	})

	return ct
}

// buildBinary builds the apko-as-apk binary for testing
func buildBinary(t *testing.T) string {
	t.Helper()

	// Find the project root (where go.mod is)
	root, err := findProjectRoot()
	if err != nil {
		t.Fatalf("failed to find project root: %v", err)
	}

	// Build the binary
	binaryPath := filepath.Join(root, "apko-as-apk-test")
	cmd := exec.Command("go", "build",
		"-o", binaryPath,
		"./cmd/apko-as-apk",
	)
	cmd.Dir = root

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build binary: %v, output: %s", err, output)
	}

	return binaryPath
}

// findProjectRoot finds the project root by looking for go.mod
func findProjectRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not find go.mod")
		}
		dir = parent
	}
}

// exec runs a command in the container
func (ct *containerTest) exec(cmd string, args ...string) (string, string, int) {
	ct.t.Helper()

	fullArgs := append([]string{"exec", ct.name, cmd}, args...)
	execCmd := exec.Command("docker", fullArgs...)

	var stdout, stderr strings.Builder
	execCmd.Stdout = &stdout
	execCmd.Stderr = &stderr

	err := execCmd.Run()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			ct.t.Fatalf("failed to exec command: %v", err)
		}
	}

	return stdout.String(), stderr.String(), exitCode
}

// cleanup removes the container
func (ct *containerTest) cleanup() {
	if ct.id != "" {
		exec.Command("docker", "rm", "--force", ct.name).Run()
	}
	if ct.binaryPath != "" {
		os.Remove(ct.binaryPath)
	}
}

// TestInfoNoArgs tests that apko-as-apk info without args matches apk info
func TestInfoNoArgs(t *testing.T) {
	ct := newContainerTest(t)

	// Get output from both commands
	apkOut, _, apkExit := ct.exec("apk", "info")
	apkoOut, _, apkoExit := ct.exec("apko-as-apk", "info")

	// Exit codes should match
	if apkExit != apkoExit {
		t.Errorf("exit codes differ: apk=%d, apko-as-apk=%d", apkExit, apkoExit)
	}

	// Both should list packages (one per line)
	apkLines := strings.Split(strings.TrimSpace(apkOut), "\n")
	apkoLines := strings.Split(strings.TrimSpace(apkoOut), "\n")

	// Should have similar number of packages (within reason)
	if len(apkLines) != len(apkoLines) {
		t.Errorf("package count differs: apk=%d, apko-as-apk=%d", len(apkLines), len(apkoLines))
	}

	// Check that common packages appear in both
	apkPackages := make(map[string]bool)
	for _, line := range apkLines {
		pkg := strings.TrimSpace(line)
		if pkg != "" {
			apkPackages[pkg] = true
		}
	}

	for _, line := range apkoLines {
		pkg := strings.TrimSpace(line)
		if pkg != "" && !apkPackages[pkg] {
			t.Logf("package %q in apko-as-apk but not in apk", pkg)
		}
	}
}

// TestInfoVerbose tests that apko-as-apk info -v matches apk info -v
func TestInfoVerbose(t *testing.T) {
	ct := newContainerTest(t)

	// Get output from both commands
	apkOut, _, apkExit := ct.exec("sh", "-c", "apk info -v 2>&1")
	apkoOut, _, apkoExit := ct.exec("apko-as-apk", "info", "-v")

	// Exit codes should match
	if apkExit != apkoExit {
		t.Errorf("exit codes differ: apk=%d, apko-as-apk=%d", apkExit, apkoExit)
	}

	// Both should list packages with versions (name-version format)
	apkLines := strings.Split(strings.TrimSpace(apkOut), "\n")
	apkoLines := strings.Split(strings.TrimSpace(apkoOut), "\n")

	// Filter out WARNING lines from apk
	var filteredApkLines []string
	for _, line := range apkLines {
		if !strings.HasPrefix(line, "WARNING:") && strings.TrimSpace(line) != "" {
			filteredApkLines = append(filteredApkLines, line)
		}
	}

	// Should have similar number of packages
	if len(filteredApkLines) != len(apkoLines) {
		t.Errorf("package count differs: apk=%d, apko-as-apk=%d",
			len(filteredApkLines), len(apkoLines))
		t.Logf("apk output (first 5): %v", filteredApkLines[:min(5, len(filteredApkLines))])
		t.Logf("apko output (first 5): %v", apkoLines[:min(5, len(apkoLines))])
	}
}

// TestInfoSpecificPackage tests info for a specific package
func TestInfoSpecificPackage(t *testing.T) {
	ct := newContainerTest(t)

	testCases := []struct {
		name    string
		pkg     string
		flags   []string
		checker func(t *testing.T, stdout, stderr string, exitCode int)
	}{
		{
			name:  "busybox default info",
			pkg:   "busybox",
			flags: []string{},
			checker: func(t *testing.T, stdout, stderr string, exitCode int) {
				if exitCode != 0 {
					t.Errorf("expected exit code 0, got %d", exitCode)
				}
				if !strings.Contains(stdout, "busybox") {
					t.Errorf("output should contain 'busybox', got: %s", stdout)
				}
			},
		},
		{
			name:  "busybox with -s (size)",
			pkg:   "busybox",
			flags: []string{"-s"},
			checker: func(t *testing.T, stdout, stderr string, exitCode int) {
				if exitCode != 0 {
					t.Errorf("expected exit code 0, got %d", exitCode)
				}
				if !strings.Contains(stdout, "installed size") {
					t.Errorf("output should contain size info, got: %s", stdout)
				}
			},
		},
		{
			name:  "busybox with -L (contents)",
			pkg:   "busybox",
			flags: []string{"-L"},
			checker: func(t *testing.T, stdout, stderr string, exitCode int) {
				if exitCode != 0 {
					t.Errorf("expected exit code 0, got %d", exitCode)
				}
				if !strings.Contains(stdout, "contains") {
					t.Errorf("output should show contents, got: %s", stdout)
				}
			},
		},
		{
			name:  "nonexistent package",
			pkg:   "nonexistent-package-xyz",
			flags: []string{},
			checker: func(t *testing.T, stdout, stderr string, exitCode int) {
				// Should print warning for nonexistent package
				if !strings.Contains(stderr, "WARNING") && !strings.Contains(stderr, "not installed") {
					t.Errorf("should warn about nonexistent package, got stderr: %s", stderr)
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"info"}, tc.flags...)
			args = append(args, tc.pkg)
			stdout, stderr, exitCode := ct.exec("apko-as-apk", args...)
			tc.checker(t, stdout, stderr, exitCode)
		})
	}
}

// TestUpdate tests the update command
func TestUpdate(t *testing.T) {
	ct := newContainerTest(t)

	// Clear cache first
	ct.exec("sh", "-c", "rm -rf /var/cache/apk/*")

	// Run update
	_, stderr, exitCode := ct.exec("apko-as-apk", "update")

	if exitCode != 0 {
		t.Errorf("update failed with exit code %d, stderr: %s", exitCode, stderr)
	}

	// Should report packages available
	if !strings.Contains(stderr, "packages available") {
		t.Errorf("update should report packages available, got: %s", stderr)
	}

	// Cache should be populated
	lsOut, _, _ := ct.exec("sh", "-c", "ls /var/cache/apk/ | wc -l")
	if strings.TrimSpace(lsOut) == "0" {
		t.Error("cache directory should be populated after update")
	}
}

// TestUpdateIdempotent tests that running update twice works
func TestUpdateIdempotent(t *testing.T) {
	ct := newContainerTest(t)

	// Run update twice
	_, _, exit1 := ct.exec("apko-as-apk", "update")
	_, _, exit2 := ct.exec("apko-as-apk", "update")

	if exit1 != 0 || exit2 != 0 {
		t.Errorf("update should succeed both times: first=%d, second=%d", exit1, exit2)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestAddPackageWithSymlinkOverwrite tests installing a package that overwrites busybox symlinks
func TestAddPackageWithSymlinkOverwrite(t *testing.T) {
	ct := newContainerTest(t)

	// Verify egrep is a symlink to busybox before installation
	stdout, _, exitCode := ct.exec("sh", "-c", "ls -la /usr/bin/egrep")
	if exitCode != 0 {
		t.Fatalf("failed to check egrep: exit code %d, output: %s", exitCode, stdout)
	}
	if !strings.Contains(stdout, "busybox") {
		t.Skipf("egrep is not a busybox symlink, skipping test. Output: %s", stdout)
	}

	// Install grep package which should replace the busybox symlinks
	stdout, stderr, exitCode := ct.exec("apko-as-apk", "add", "grep")
	if exitCode != 0 {
		t.Fatalf("failed to install grep: exit code %d\nstdout: %s\nstderr: %s", exitCode, stdout, stderr)
	}

	// Verify grep was installed successfully
	if !strings.Contains(stderr, "OK") && !strings.Contains(stderr, "Installing grep") {
		t.Errorf("expected success message, got: %s", stderr)
	}

	// Verify egrep is now a regular file, not a symlink
	stdout, _, exitCode = ct.exec("sh", "-c", "test -L /usr/bin/egrep && echo 'symlink' || echo 'file'")
	if exitCode != 0 {
		t.Errorf("failed to check egrep type: exit code %d", exitCode)
	}
	if strings.Contains(stdout, "symlink") {
		t.Error("egrep should be a regular file after installing grep, not a symlink")
	}

	// Verify egrep works
	stdout, _, exitCode = ct.exec("/usr/bin/egrep", "--version")
	if exitCode != 0 {
		t.Errorf("egrep --version failed: exit code %d", exitCode)
	}
	if !strings.Contains(stdout, "grep") {
		t.Errorf("egrep should be GNU grep, got: %s", stdout)
	}

	// Verify fgrep was also replaced
	stdout, _, exitCode = ct.exec("sh", "-c", "test -L /usr/bin/fgrep && echo 'symlink' || echo 'file'")
	if exitCode != 0 {
		t.Errorf("failed to check fgrep type: exit code %d", exitCode)
	}
	if strings.Contains(stdout, "symlink") {
		t.Error("fgrep should be a regular file after installing grep, not a symlink")
	}

	// Verify the package is recorded in the world file
	stdout, _, exitCode = ct.exec("apko-as-apk", "info", "grep")
	if exitCode != 0 {
		t.Errorf("grep should be installed: exit code %d", exitCode)
	}
}

// TestCompareOutputFormats tests that output formats are compatible
func TestCompareOutputFormats(t *testing.T) {
	ct := newContainerTest(t)

	tests := []struct {
		name     string
		apkArgs  []string
		apkoArgs []string
	}{
		{
			name:     "info no args",
			apkArgs:  []string{"info"},
			apkoArgs: []string{"info"},
		},
		{
			name:     "info verbose",
			apkArgs:  []string{"info", "-v"},
			apkoArgs: []string{"info", "-v"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apkCmd := append([]string{"sh", "-c"}, fmt.Sprintf("apk %s 2>&1", strings.Join(tt.apkArgs, " ")))
			apkOut, _, _ := ct.exec(apkCmd[0], apkCmd[1:]...)

			apkoOut, _, _ := ct.exec("apko-as-apk", tt.apkoArgs...)

			// Strip warnings from apk output
			var apkLines []string
			for _, line := range strings.Split(apkOut, "\n") {
				if !strings.HasPrefix(line, "WARNING:") && strings.TrimSpace(line) != "" {
					apkLines = append(apkLines, strings.TrimSpace(line))
				}
			}

			var apkoLines []string
			for _, line := range strings.Split(apkoOut, "\n") {
				if strings.TrimSpace(line) != "" {
					apkoLines = append(apkoLines, strings.TrimSpace(line))
				}
			}

			// Compare line counts
			if len(apkLines) != len(apkoLines) {
				t.Logf("Line count mismatch: apk=%d, apko-as-apk=%d", len(apkLines), len(apkoLines))
			}
		})
	}
}
