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
	"chainguard.dev/apko/pkg/apk/auth"
	"chainguard.dev/apko/pkg/build/types"
)

// ResolvedPackage represents a package that has been resolved to a specific
// version and download URL.
type ResolvedPackage struct {
	Ecosystem     string
	Name          string
	Version       string
	URL           string
	Checksum      string // "sha256:<hex>"
	SignatureURL  string // optional: signature bundle URL (from data-signature)
	ProvenanceURL string // optional: provenance data URL (from data-provenance)

	// InstalledSize is populated after installation with the approximate
	// bytes written for this package. Used for layering budget decisions.
	InstalledSize uint64
}

// OwnerName returns the namespaced owner string used for filesystem tagging
// and layer routing (e.g. "python:flask"). The colon ensures no collision
// with APK package names.
func (rp ResolvedPackage) OwnerName() string {
	return rp.Ecosystem + ":" + rp.Name
}

// Installer is the interface that ecosystem package installers must implement.
type Installer interface {
	// Name returns the ecosystem name (e.g., "python").
	Name() string
	// Resolve resolves the requested packages to specific versions and URLs.
	Resolve(ctx context.Context, config types.EcosystemConfig, arch types.Architecture, a auth.Authenticator) ([]ResolvedPackage, error)
	// Install extracts resolved packages into the filesystem.
	// Returns environment variables that should be set in the image configuration.
	Install(ctx context.Context, fs apkfs.FullFS, packages []ResolvedPackage, config types.EcosystemConfig, a auth.Authenticator) (map[string]string, error)
}

// RequiredAPKPackagesFunc returns APK packages that an ecosystem requires.
type RequiredAPKPackagesFunc func(config types.EcosystemConfig) []string

var (
	registryMu   sync.RWMutex
	registry     = map[string]func() Installer{}
	apkPkgsFuncs = map[string]RequiredAPKPackagesFunc{}
)

// Register registers an ecosystem installer factory.
func Register(name string, factory func() Installer) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[name] = factory
}

// RegisterRequiredAPKPackages registers a function that returns APK packages
// required by the named ecosystem.
func RegisterRequiredAPKPackages(name string, fn RequiredAPKPackagesFunc) {
	registryMu.Lock()
	defer registryMu.Unlock()
	apkPkgsFuncs[name] = fn
}

// RequiredPackages returns APK packages required by all configured ecosystems.
// These should be injected into ImageContents.Packages before resolution.
func RequiredPackages(ecosystems map[string]types.EcosystemConfig) []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	var pkgs []string
	for name, config := range ecosystems {
		if fn, ok := apkPkgsFuncs[name]; ok {
			pkgs = append(pkgs, fn(config)...)
		}
	}
	return pkgs
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

// OwnerTagger is implemented by filesystems that support tagging files
// with an owner name for layering purposes.
type OwnerTagger interface {
	SetCurrentOwner(owner string)
	OwnerSize(owner string) uint64
}

// InstallAll installs packages for all configured ecosystems.
// Returns environment variables, the resolved packages with InstalledSize
// populated, and any error.
//
// Installers are responsible for tagging files with per-package ownership
// via the OwnerTagger interface on the filesystem, if supported.
func InstallAll(ctx context.Context, fs apkfs.FullFS, ecosystems map[string]types.EcosystemConfig, arch types.Architecture, a auth.Authenticator) (map[string]string, []ResolvedPackage, error) {
	env := map[string]string{}
	var installed []ResolvedPackage

	for name, config := range ecosystems {
		installer, ok := Get(name)
		if !ok {
			return nil, nil, fmt.Errorf("unknown ecosystem: %s", name)
		}
		resolved, err := installer.Resolve(ctx, config, arch, a)
		if err != nil {
			return nil, nil, fmt.Errorf("resolving %s packages: %w", name, err)
		}
		if len(resolved) == 0 {
			continue
		}

		vars, err := installer.Install(ctx, fs, resolved, config, a)
		if err != nil {
			return nil, nil, fmt.Errorf("installing %s packages: %w", name, err)
		}

		installed = append(installed, resolved...)

		for k, v := range vars {
			env[k] = v
		}
	}
	return env, installed, nil
}
