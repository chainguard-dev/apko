// Copyright 2023 Chainguard, Inc.
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

package impl

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
)

// getWorldPackages get list of packages that should be installed, according to /etc/apk/world
func (a *APKImplementation) GetWorld() ([]string, error) {
	worldFile, err := a.fs.Open(worldFilePath)
	if err != nil {
		return nil, fmt.Errorf("could not open world file in %s at %s: %w", a.fs, worldFilePath, err)
	}
	defer worldFile.Close()
	worldData, err := io.ReadAll(worldFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read world file: %w", err)
	}
	return strings.Fields(string(worldData)), nil
}

// SetWorld sets the list of world packages intended to be installed.
// The base directory of /etc/apk must already exist, i.e. this only works on an initialized APK database.
func (a *APKImplementation) SetWorld(packages []string) error {
	a.logger.Infof("setting apk world")

	// sort them before writing
	copied := make([]string, len(packages))
	copy(copied, packages)
	sort.Strings(copied)

	data := strings.Join(copied, "\n")

	// #nosec G306 -- apk world must be publicly readable
	if err := a.fs.WriteFile(filepath.Join("etc", "apk", "world"),
		[]byte(data), 0o644); err != nil {
		return fmt.Errorf("failed to write apk world: %w", err)
	}

	return nil
}
