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
	"context"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/chainguard-dev/clog"

	"chainguard.dev/apko/pkg/apk/auth"
	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/ecosystem"
)

func init() {
	ecosystem.Register("python", func() ecosystem.Installer {
		return &installer{}
	})
	ecosystem.RegisterRequiredAPKPackages("python", RequiredAPKPackages)
}

// RequiredAPKPackages returns the APK packages needed for the configured
// Python version. When python_version is set, it injects both the base
// interpreter and the full python package so users don't need to list them
// manually in contents.packages.
func RequiredAPKPackages(config types.EcosystemConfig) []string {
	if config.PythonVersion == "" {
		return nil
	}
	return []string{
		"python-" + config.PythonVersion + "-base",
		"python-" + config.PythonVersion,
	}
}

type installer struct{}

func (i *installer) Name() string { return "python" }

func (i *installer) Resolve(ctx context.Context, config types.EcosystemConfig, arch types.Architecture, a auth.Authenticator) ([]ecosystem.ResolvedPackage, error) {
	if len(config.Packages) == 0 {
		return nil, nil
	}

	specs := make([]packageSpec, 0, len(config.Packages))
	for _, pkg := range config.Packages {
		specs = append(specs, parsePackageSpec(pkg))
	}

	indexes := config.Indexes
	if len(indexes) == 0 {
		indexes = []string{defaultIndex}
	}

	pythonVersion := config.PythonVersion
	if pythonVersion == "" {
		return nil, fmt.Errorf("python_version is required in ecosystem python config")
	}

	return resolvePackages(ctx, specs, indexes, pythonVersion, arch, a)
}

func (i *installer) Install(ctx context.Context, fsys apkfs.FullFS, packages []ecosystem.ResolvedPackage, config types.EcosystemConfig, a auth.Authenticator) (map[string]string, error) {
	log := clog.FromContext(ctx)

	pythonVersion := detectPythonVersion(fsys)
	if pythonVersion == "" {
		return nil, fmt.Errorf("no Python installation found in filesystem; install python3 via APK first")
	}
	log.Infof("detected Python %s for python ecosystem install", pythonVersion)

	var sitePackagesPath string
	if config.Venv != "" {
		venvPath := strings.TrimPrefix(config.Venv, "/")
		if err := createVenv(fsys, venvPath, pythonVersion); err != nil {
			return nil, fmt.Errorf("creating virtual environment at %s: %w", config.Venv, err)
		}
		sitePackagesPath = filepath.Join(venvPath, "lib", "python"+pythonVersion, "site-packages")
		log.Infof("using virtual environment at %s", config.Venv)
	} else {
		sitePackagesPath = fmt.Sprintf("usr/lib/python%s/site-packages", pythonVersion)
	}

	if err := fsys.MkdirAll(sitePackagesPath, 0755); err != nil {
		return nil, fmt.Errorf("creating site-packages directory: %w", err)
	}

	tagger, _ := fsys.(ecosystem.OwnerTagger)

	for idx, pkg := range packages {
		log.Infof("installing python package %s==%s", pkg.Name, pkg.Version)

		if tagger != nil {
			tagger.SetCurrentOwner(pkg.OwnerName())
		}

		data, err := downloadWheel(ctx, pkg.URL, a)
		if err != nil {
			return nil, fmt.Errorf("downloading %s: %w", pkg.Name, err)
		}

		if err := verifyChecksum(data, pkg.Checksum); err != nil {
			return nil, fmt.Errorf("verifying %s: %w", pkg.Name, err)
		}

		if err := extractWheel(fsys, data, sitePackagesPath); err != nil {
			return nil, fmt.Errorf("extracting %s: %w", pkg.Name, err)
		}

		if err := writeInstallerFile(fsys, sitePackagesPath, data); err != nil {
			log.Debugf("could not write INSTALLER file for %s: %v", pkg.Name, err)
		}

		if isChainguardSource(pkg.URL) {
			if err := writePackageSBOM(fsys, sitePackagesPath, data, pkg); err != nil {
				log.Debugf("could not write SBOM for %s: %v", pkg.Name, err)
			}
		}

		if tagger != nil {
			tagger.SetCurrentOwner("")
			packages[idx].InstalledSize = tagger.OwnerSize(pkg.OwnerName())
		}
	}

	// When using a venv, set VIRTUAL_ENV and prepend its bin/ to PATH.
	if config.Venv != "" {
		venvBin := filepath.Join(config.Venv, "bin")
		return map[string]string{
			"VIRTUAL_ENV": config.Venv,
			"PATH":        venvBin + ":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		}, nil
	}

	return nil, nil
}

// createVenv sets up a virtual environment directory structure.
func createVenv(fsys apkfs.FullFS, venvPath, pythonVersion string) error {
	// Create directory structure
	dirs := []string{
		filepath.Join(venvPath, "bin"),
		filepath.Join(venvPath, "include"),
		filepath.Join(venvPath, "lib", "python"+pythonVersion, "site-packages"),
	}
	for _, dir := range dirs {
		if err := fsys.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("creating %s: %w", dir, err)
		}
	}

	// Write pyvenv.cfg
	cfg := fmt.Sprintf(
		"home = /usr/bin\ninclude-system-site-packages = false\nversion = %s\n",
		pythonVersion,
	)
	cfgPath := filepath.Join(venvPath, "pyvenv.cfg")
	if err := fsys.WriteFile(cfgPath, []byte(cfg), 0644); err != nil {
		return fmt.Errorf("writing pyvenv.cfg: %w", err)
	}

	// Create symlinks in bin/
	pythonBin := "/usr/bin/python" + pythonVersion
	binPath := filepath.Join(venvPath, "bin")
	symlinks := map[string]string{
		"python":                 pythonBin,
		"python3":                pythonBin,
		"python" + pythonVersion: pythonBin,
	}
	for name, target := range symlinks {
		linkPath := filepath.Join(binPath, name)
		if err := fsys.Symlink(target, linkPath); err != nil {
			return fmt.Errorf("creating symlink %s: %w", linkPath, err)
		}
	}

	return nil
}

// detectPythonVersion scans the filesystem for a Python installation and
// returns the version string (e.g., "3.12").
func detectPythonVersion(fsys apkfs.FullFS) string {
	entries, err := fsys.ReadDir("usr/lib")
	if err != nil {
		return ""
	}

	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, "python3.") && entry.IsDir() {
			return strings.TrimPrefix(name, "python")
		}
	}

	return ""
}

// downloadWheel downloads a wheel file from the given URL.
func downloadWheel(ctx context.Context, url string, a auth.Authenticator) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	if a != nil {
		if err := a.AddAuth(ctx, req); err != nil {
			return nil, fmt.Errorf("adding auth for %s: %w", url, err)
		}
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d downloading %s", resp.StatusCode, url)
	}

	return io.ReadAll(resp.Body)
}
