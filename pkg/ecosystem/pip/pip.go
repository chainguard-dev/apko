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
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/chainguard-dev/clog"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/ecosystem"
)

func init() {
	ecosystem.Register("python", func() ecosystem.Installer {
		return &installer{}
	})
}

type installer struct{}

func (i *installer) Name() string { return "python" }

func (i *installer) Resolve(ctx context.Context, config types.EcosystemConfig, arch types.Architecture) ([]ecosystem.ResolvedPackage, error) {
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

	// We need a Python version to filter wheels. We'll use a default that
	// callers can override via the config, or detect later during install.
	pythonVersion := config.PythonVersion
	if pythonVersion == "" {
		pythonVersion = "3.12"
	}

	return resolvePackages(ctx, specs, indexes, pythonVersion, arch)
}

func (i *installer) Install(ctx context.Context, fsys apkfs.FullFS, packages []ecosystem.ResolvedPackage) error {
	log := clog.FromContext(ctx)

	pythonVersion := detectPythonVersion(fsys)
	if pythonVersion == "" {
		return fmt.Errorf("no Python installation found in filesystem; install python3 via APK first")
	}
	log.Infof("detected Python %s for pip ecosystem install", pythonVersion)

	sitePackagesPath := fmt.Sprintf("usr/lib/python%s/site-packages", pythonVersion)
	if err := fsys.MkdirAll(sitePackagesPath, 0755); err != nil {
		return fmt.Errorf("creating site-packages directory: %w", err)
	}

	for _, pkg := range packages {
		log.Infof("installing pip package %s==%s", pkg.Name, pkg.Version)

		data, err := downloadWheel(ctx, pkg.URL)
		if err != nil {
			return fmt.Errorf("downloading %s: %w", pkg.Name, err)
		}

		if err := verifyChecksum(data, pkg.Checksum); err != nil {
			return fmt.Errorf("verifying %s: %w", pkg.Name, err)
		}

		if err := extractWheel(fsys, data, sitePackagesPath); err != nil {
			return fmt.Errorf("extracting %s: %w", pkg.Name, err)
		}

		if err := writeInstallerFile(fsys, sitePackagesPath, data); err != nil {
			log.Debugf("could not write INSTALLER file for %s: %v", pkg.Name, err)
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
func downloadWheel(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
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
