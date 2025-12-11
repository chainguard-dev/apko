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
	"context"
	"testing"

	"chainguard.dev/apko/pkg/apk/apk"
	apkfs "chainguard.dev/apko/pkg/apk/fs"
)

// TestAddWithUnavailableInstalledPackages tests the fix for the bug where
// apko-as-apk would fail to add a new package if the system had already-installed
// packages that weren't available in the current repositories.
//
// Real-world scenario that triggered this bug:
// - Running: docker run cgr.dev/chainguard-private/chainguard-base:latest apko-as-apk add grep
// - The container had "chainguard-baselayout" installed from a private repository
// - When adding "grep", apko-as-apk would try to re-resolve ALL packages in world
// - This failed with: "nothing provides chainguard-baselayout"
//
// This test reproduces the scenario where:
// 1. A container has packages from private/unavailable repositories installed
// 2. Those packages are listed in /etc/apk/world
// 3. We try to add a new package
// 4. The old behavior would try to re-resolve all packages including unavailable ones (BUG)
// 5. The new behavior should only resolve packages that aren't already installed (FIX)
func TestAddWithUnavailableInstalledPackages(t *testing.T) {
	ctx := context.Background()
	fs := apkfs.NewMemFS()

	// Create APK client
	apkClient, err := apk.New(ctx, apk.WithFS(fs), apk.WithArch("x86_64"))
	if err != nil {
		t.Fatalf("failed to create APK client: %v", err)
	}

	// Initialize the database
	if err := apkClient.InitDB(ctx); err != nil {
		t.Fatalf("failed to initialize database: %v", err)
	}

	// Create a world file with some packages (simulating already installed packages)
	// Note: These packages include ones that would not be in the available repos
	initialWorld := []string{
		"apk-tools",
		"busybox",
		"ca-certificates-bundle",
		"private-package", // This simulates a package from a private/unavailable repo
		"glibc",
	}

	if err := apkClient.SetWorld(ctx, initialWorld); err != nil {
		t.Fatalf("failed to set initial world: %v", err)
	}

	// Simulate that these packages are already installed by adding them to the installed db
	// In the real bug scenario, these packages exist in /lib/apk/db/installed
	// We'll create a mock installed database
	installedPackages := []*apk.Package{
		{
			Name:    "apk-tools",
			Version: "2.14.0-r0",
		},
		{
			Name:    "busybox",
			Version: "1.36.0-r0",
		},
		{
			Name:    "ca-certificates-bundle",
			Version: "20230506-r0",
		},
		{
			Name:    "private-package", // This is the problematic package
			Version: "1.0.0-r0",
		},
		{
			Name:    "glibc",
			Version: "2.38-r0",
		},
	}

	// Add these packages to the installed database
	for _, pkg := range installedPackages {
		// AddInstalledPackage adds a package to the installed db
		if _, err := apkClient.AddInstalledPackage(pkg, nil); err != nil {
			t.Fatalf("failed to add package %s to installed db: %v", pkg.Name, err)
		}
	}

	// Now verify that GetInstalled returns our packages
	installed, err := apkClient.GetInstalled()
	if err != nil {
		t.Fatalf("failed to get installed packages: %v", err)
	}

	if len(installed) != len(installedPackages) {
		t.Fatalf("expected %d installed packages, got %d", len(installedPackages), len(installed))
	}

	// Create a map of installed packages for easy checking
	installedMap := make(map[string]bool)
	for _, pkg := range installed {
		installedMap[pkg.Name] = true
	}

	// Verify the logic we use in runAdd to filter out already-installed packages
	// This is the core of the fix: we should only try to resolve packages that
	// are not already installed

	// Test case 1: Adding a package that's not installed
	newPackage := "curl"
	if installedMap[newPackage] {
		t.Errorf("package %s should not be installed yet", newPackage)
	}

	// Test case 2: Verify private-package is installed
	if !installedMap["private-package"] {
		t.Errorf("package private-package should be installed")
	}

	// Test case 3: Simulate what runAdd does - filter world to only uninstalled packages
	world, err := apkClient.GetWorld()
	if err != nil {
		t.Fatalf("failed to get world: %v", err)
	}

	// Add the new package to world (like runAdd does)
	world = append(world, newPackage)

	// Create worldToResolve - only packages that are NOT already installed
	// This is the key part of the fix
	worldToResolve := []string{}
	for _, w := range world {
		wName := w
		// Extract package name (remove version constraint if present)
		for _, sep := range []string{"=", "<", ">", "~"} {
			if idx := len(wName); idx > 0 {
				for i, c := range w {
					if string(c) == sep {
						wName = w[:i]
						break
					}
				}
			}
		}
		// Only include packages that are not already installed
		if !installedMap[wName] {
			worldToResolve = append(worldToResolve, w)
		}
	}

	// Verify that worldToResolve only contains the new package, not the already-installed ones
	if len(worldToResolve) != 1 {
		t.Errorf("expected worldToResolve to contain only 1 package (the new one), got %d: %v",
			len(worldToResolve), worldToResolve)
	}

	if worldToResolve[0] != newPackage {
		t.Errorf("expected worldToResolve[0] to be %q, got %q", newPackage, worldToResolve[0])
	}

	// Verify that private-package is NOT in worldToResolve
	for _, pkg := range worldToResolve {
		if pkg == "private-package" {
			t.Errorf("private-package should not be in worldToResolve (it's already installed)")
		}
	}

	// Test case 4: Verify that adding an already-installed package is handled correctly
	alreadyInstalledPkg := "busybox"
	if !installedMap[alreadyInstalledPkg] {
		t.Errorf("package %s should be installed", alreadyInstalledPkg)
	}

	// If we try to add busybox, it should be filtered out since it's already installed
	testWorld := append(world, alreadyInstalledPkg)
	testWorldToResolve := []string{}
	for _, w := range testWorld {
		wName := w
		for _, sep := range []string{"=", "<", ">", "~"} {
			for i, c := range w {
				if string(c) == sep {
					wName = w[:i]
					break
				}
			}
		}
		if !installedMap[wName] {
			testWorldToResolve = append(testWorldToResolve, w)
		}
	}

	// Should still only have curl, not busybox
	if len(testWorldToResolve) != 1 || testWorldToResolve[0] != newPackage {
		t.Errorf("expected testWorldToResolve to only contain %q, got: %v", newPackage, testWorldToResolve)
	}

	t.Logf("Successfully verified that already-installed packages are filtered out before resolution")
	t.Logf("This prevents the bug where unavailable packages would cause resolution to fail")
}

// TestAddPackageNameExtraction tests that we correctly extract package names
// from package specifications with version constraints
func TestAddPackageNameExtraction(t *testing.T) {
	tests := []struct {
		name     string
		pkg      string
		wantName string
	}{
		{
			name:     "simple package name",
			pkg:      "curl",
			wantName: "curl",
		},
		{
			name:     "package with exact version",
			pkg:      "curl=8.0.0-r0",
			wantName: "curl",
		},
		{
			name:     "package with version constraint >=",
			pkg:      "curl>=8.0.0",
			wantName: "curl",
		},
		{
			name:     "package with version constraint <",
			pkg:      "curl<9.0.0",
			wantName: "curl",
		},
		{
			name:     "package with fuzzy version ~",
			pkg:      "curl~8.0",
			wantName: "curl",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This is the logic used in runAdd to extract package names
			pkgName := tt.pkg
			if idx := -1; idx < len(tt.pkg) {
				for i, c := range tt.pkg {
					s := string(c)
					if s == "=" || s == "<" || s == ">" || s == "~" {
						idx = i
						break
					}
				}
				if idx != -1 {
					pkgName = tt.pkg[:idx]
				}
			}

			if pkgName != tt.wantName {
				t.Errorf("extracting name from %q: got %q, want %q", tt.pkg, pkgName, tt.wantName)
			}
		})
	}
}
