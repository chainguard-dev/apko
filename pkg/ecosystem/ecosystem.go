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

package ecosystem

import (
	"context"
	"fmt"
	"sync"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/build/types"
)

// ResolvedPackage represents a package that has been resolved to a specific
// version and download URL.
type ResolvedPackage struct {
	Ecosystem string
	Name      string
	Version   string
	URL       string
	Checksum  string // "sha256:<hex>"
}

// Installer is the interface that ecosystem package installers must implement.
type Installer interface {
	// Name returns the ecosystem name (e.g., "python").
	Name() string
	// Resolve resolves the requested packages to specific versions and URLs.
	Resolve(ctx context.Context, config types.EcosystemConfig, arch types.Architecture) ([]ResolvedPackage, error)
	// Install extracts resolved packages into the filesystem.
	Install(ctx context.Context, fs apkfs.FullFS, packages []ResolvedPackage) error
}

var (
	registryMu sync.RWMutex
	registry   = map[string]func() Installer{}
)

// Register registers an ecosystem installer factory.
func Register(name string, factory func() Installer) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[name] = factory
}

// Get returns an installer for the named ecosystem.
func Get(name string) (Installer, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	factory, ok := registry[name]
	if !ok {
		return nil, false
	}
	return factory(), true
}

// InstallAll installs packages for all configured ecosystems.
func InstallAll(ctx context.Context, fs apkfs.FullFS, ecosystems map[string]types.EcosystemConfig, arch types.Architecture) error {
	for name, config := range ecosystems {
		installer, ok := Get(name)
		if !ok {
			return fmt.Errorf("unknown ecosystem: %s", name)
		}
		resolved, err := installer.Resolve(ctx, config, arch)
		if err != nil {
			return fmt.Errorf("resolving %s packages: %w", name, err)
		}
		if len(resolved) == 0 {
			continue
		}
		if err := installer.Install(ctx, fs, resolved); err != nil {
			return fmt.Errorf("installing %s packages: %w", name, err)
		}
	}
	return nil
}
