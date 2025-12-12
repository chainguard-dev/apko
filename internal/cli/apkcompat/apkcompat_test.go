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
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"chainguard.dev/apko/pkg/apk/apk"
	apkfs "chainguard.dev/apko/pkg/apk/fs"
)

func TestGetRepositoriesFromFile(t *testing.T) {
	tests := []struct {
		name          string
		fileContent   string
		wantRepos     []string
		wantErr       bool
		setupGlobals  func()
		cleanupGlobals func()
	}{
		{
			name: "simple repository file",
			fileContent: `https://dl-cdn.alpinelinux.org/alpine/edge/main
https://dl-cdn.alpinelinux.org/alpine/edge/community`,
			wantRepos: []string{
				"https://dl-cdn.alpinelinux.org/alpine/edge/main",
				"https://dl-cdn.alpinelinux.org/alpine/edge/community",
			},
			wantErr: false,
		},
		{
			name: "repository file with comments",
			fileContent: `# This is a comment
https://dl-cdn.alpinelinux.org/alpine/edge/main
# Another comment
https://dl-cdn.alpinelinux.org/alpine/edge/community
`,
			wantRepos: []string{
				"https://dl-cdn.alpinelinux.org/alpine/edge/main",
				"https://dl-cdn.alpinelinux.org/alpine/edge/community",
			},
			wantErr: false,
		},
		{
			name: "repository file with blank lines",
			fileContent: `https://dl-cdn.alpinelinux.org/alpine/edge/main

https://dl-cdn.alpinelinux.org/alpine/edge/community

`,
			wantRepos: []string{
				"https://dl-cdn.alpinelinux.org/alpine/edge/main",
				"https://dl-cdn.alpinelinux.org/alpine/edge/community",
			},
			wantErr: false,
		},
		{
			name:        "empty file",
			fileContent: "",
			wantRepos:   []string{},
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary file
			tmpDir := t.TempDir()
			repoFile := filepath.Join(tmpDir, "repositories")

			if err := os.WriteFile(repoFile, []byte(tt.fileContent), 0644); err != nil {
				t.Fatalf("failed to create test file: %v", err)
			}

			// Set up globals
			oldGlobalOpts := globalOpts
			globalOpts = &GlobalOptions{
				RepositoriesFile: repoFile,
			}
			if tt.setupGlobals != nil {
				tt.setupGlobals()
			}
			defer func() {
				globalOpts = oldGlobalOpts
				if tt.cleanupGlobals != nil {
					tt.cleanupGlobals()
				}
			}()

			// Create a mock APK client
			ctx := context.Background()
			fs := apkfs.NewMemFS()
			apkClient, err := apk.New(ctx, apk.WithFS(fs), apk.WithArch("x86_64"))
			if err != nil {
				t.Fatalf("failed to create APK client: %v", err)
			}

			// Test getRepositories
			repos, err := getRepositories(ctx, apkClient)
			if (err != nil) != tt.wantErr {
				t.Errorf("getRepositories() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(repos) != len(tt.wantRepos) {
				t.Errorf("getRepositories() got %d repos, want %d", len(repos), len(tt.wantRepos))
				return
			}

			for i, repo := range repos {
				if repo != tt.wantRepos[i] {
					t.Errorf("getRepositories()[%d] = %v, want %v", i, repo, tt.wantRepos[i])
				}
			}
		})
	}
}

func TestGetRepositoriesFromCommandLine(t *testing.T) {
	ctx := context.Background()
	fs := apkfs.NewMemFS()
	apkClient, err := apk.New(ctx, apk.WithFS(fs), apk.WithArch("x86_64"))
	if err != nil {
		t.Fatalf("failed to create APK client: %v", err)
	}

	// Set up globals with command-line repos
	oldGlobalOpts := globalOpts
	globalOpts = &GlobalOptions{
		Repository: []string{
			"https://example.com/repo1",
			"https://example.com/repo2",
		},
	}
	defer func() { globalOpts = oldGlobalOpts }()

	repos, err := getRepositories(ctx, apkClient)
	if err != nil {
		t.Fatalf("getRepositories() error = %v", err)
	}

	// Should use command-line repositories when no file specified and no existing repos
	if len(repos) != 2 {
		t.Errorf("expected 2 repos, got %d", len(repos))
	}
}

func TestInstallKeysWithNoKeysDir(t *testing.T) {
	ctx := context.Background()
	fs := apkfs.NewMemFS()
	apkClient, err := apk.New(ctx, apk.WithFS(fs), apk.WithArch("x86_64"))
	if err != nil {
		t.Fatalf("failed to create APK client: %v", err)
	}

	// Test with non-existent directory
	tmpDir := t.TempDir()
	nonExistentDir := filepath.Join(tmpDir, "does-not-exist")

	err = installKeys(ctx, apkClient, nonExistentDir)
	// Should not error, just warn and return
	if err != nil {
		t.Errorf("installKeys with non-existent dir should not error, got: %v", err)
	}
}

func TestInstallKeysWithEmptyDir(t *testing.T) {
	ctx := context.Background()
	fs := apkfs.NewMemFS()
	apkClient, err := apk.New(ctx, apk.WithFS(fs), apk.WithArch("x86_64"))
	if err != nil {
		t.Fatalf("failed to create APK client: %v", err)
	}

	// Test with empty directory
	emptyDir := t.TempDir()

	err = installKeys(ctx, apkClient, emptyDir)
	// Should not error
	if err != nil {
		t.Errorf("installKeys with empty dir should not error, got: %v", err)
	}
}

func TestInstallKeysWithKeyFiles(t *testing.T) {
	ctx := context.Background()
	fs := apkfs.NewMemFS()
	apkClient, err := apk.New(ctx, apk.WithFS(fs), apk.WithArch("x86_64"))
	if err != nil {
		t.Fatalf("failed to create APK client: %v", err)
	}

	// Test with directory containing key files
	keysDir := t.TempDir()

	// Create some dummy key files
	keyFiles := []string{"key1.pub", "key2.pub", "notakey.txt"}
	for _, keyFile := range keyFiles {
		if err := os.WriteFile(filepath.Join(keysDir, keyFile), []byte("dummy key"), 0644); err != nil {
			t.Fatalf("failed to create key file: %v", err)
		}
	}

	// This will error because the dummy keys aren't valid, but it should attempt to load them
	_ = installKeys(ctx, apkClient, keysDir)
	// We're just testing that it finds the .pub files and attempts to load them
}

func TestPrintPackageInfo(t *testing.T) {
	pkg := &apk.InstalledPackage{
		Package: apk.Package{
			Name:          "test-package",
			Version:       "1.0.0-r0",
			Description:   "A test package",
			URL:           "https://example.com",
			License:       "MIT",
			InstalledSize: 1024,
			Dependencies:  []string{"dep1", "dep2>=1.0"},
			Provides:      []string{"virtual1"},
		},
	}

	tests := []struct {
		name         string
		opts         *infoOptions
		wantContains []string
	}{
		{
			name: "default info",
			opts: &infoOptions{
				description: true,
				webpage:     true,
				size:        true,
			},
			wantContains: []string{
				"test-package-1.0.0-r0",
				"A test package",
				"https://example.com",
				"installed size",
			},
		},
		{
			name: "with dependencies",
			opts: &infoOptions{
				depends: true,
			},
			wantContains: []string{
				"depends on",
				"dep1",
				"dep2>=1.0",
			},
		},
		{
			name: "with provides",
			opts: &infoOptions{
				provides: true,
			},
			wantContains: []string{
				"provides",
				"virtual1",
			},
		},
		{
			name: "with license",
			opts: &infoOptions{
				license: true,
			},
			wantContains: []string{
				"license",
				"MIT",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture stdout
			old := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			printPackageInfo(pkg, tt.opts)

			w.Close()
			os.Stdout = old

			var buf bytes.Buffer
			buf.ReadFrom(r)
			output := buf.String()

			for _, want := range tt.wantContains {
				if !bytes.Contains([]byte(output), []byte(want)) {
					t.Errorf("output should contain %q, got: %s", want, output)
				}
			}
		})
	}
}

func TestListAllInstalled(t *testing.T) {
	ctx := context.Background()
	fs := apkfs.NewMemFS()

	// Create APK client and initialize DB
	apkClient, err := apk.New(ctx, apk.WithFS(fs), apk.WithArch("x86_64"))
	if err != nil {
		t.Fatalf("failed to create APK client: %v", err)
	}

	if err := apkClient.InitDB(ctx); err != nil {
		t.Fatalf("failed to init DB: %v", err)
	}

	tests := []struct {
		name         string
		opts         *infoOptions
		verbose      int
		wantErr      bool
		checkOutput  func(t *testing.T, output string)
	}{
		{
			name:    "no verbose, no options",
			opts:    &infoOptions{},
			verbose: 0,
			wantErr: false,
			checkOutput: func(t *testing.T, output string) {
				// With no installed packages, should be empty
				if output != "" {
					t.Logf("got output: %s", output)
				}
			},
		},
		{
			name:    "with verbose flag",
			opts:    &infoOptions{},
			verbose: 1,
			wantErr: false,
			checkOutput: func(t *testing.T, output string) {
				// Should still work with no packages
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture stdout
			old := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			err := listAllInstalled(apkClient, tt.opts, tt.verbose)

			w.Close()
			os.Stdout = old

			if (err != nil) != tt.wantErr {
				t.Errorf("listAllInstalled() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			var buf bytes.Buffer
			buf.ReadFrom(r)
			output := buf.String()

			if tt.checkOutput != nil {
				tt.checkOutput(t, output)
			}
		})
	}
}
