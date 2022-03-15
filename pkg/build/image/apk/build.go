// Copyright 2022 Chainguard, Inc.
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

package apk

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sync/errgroup"
)

// Builds the image in Context.WorkDir.
func (ab *apkBuilder) BuildImage() error {
	ab.Log.Printf("doing pre-flight checks")
	if err := ab.ImageConfiguration.Validate(); err != nil {
		return fmt.Errorf("failed to validate configuration: %w", err)
	}

	ab.Log.Printf("building image fileystem in %s", ab.WorkDir)

	// initialize apk
	if err := ab.InitApkDB(); err != nil {
		return fmt.Errorf("failed to initialize apk database: %w", err)
	}

	var eg errgroup.Group

	eg.Go(func() error {
		if err := ab.InitApkKeyring(); err != nil {
			return fmt.Errorf("failed to initialize apk keyring: %w", err)
		}
		return nil
	})

	eg.Go(func() error {
		if err := ab.InitApkRepositories(); err != nil {
			return fmt.Errorf("failed to initialize apk repositories: %w", err)
		}
		return nil
	})

	eg.Go(func() error {
		if err := ab.InitApkWorld(); err != nil {
			return fmt.Errorf("failed to initialize apk world: %w", err)
		}
		return nil
	})

	if err := eg.Wait(); err != nil {
		return err
	}

	// sync reality with desired apk world
	if err := ab.FixateApkWorld(); err != nil {
		return fmt.Errorf("failed to fixate apk world: %w", err)
	}

	eg.Go(func() error {
		if err := ab.normalizeApkScriptsTar(); err != nil {
			return fmt.Errorf("failed to normalize scripts.tar: %w", err)
		}
		return nil
	})

	eg.Go(func() error {
		if err := ab.MutateAccounts(); err != nil {
			return fmt.Errorf("failed to mutate accounts: %w", err)
		}
		return nil
	})

	if err := eg.Wait(); err != nil {
		return err
	}

	// maybe install busybox symlinks
	if err := ab.InstallBusyboxSymlinks(); err != nil {
		return fmt.Errorf("failed to install busybox symlinks: %w", err)
	}

	// write service supervision tree
	if err := ab.s6.WriteSupervisionTree(ab.ImageConfiguration.Entrypoint.Services); err != nil {
		return fmt.Errorf("failed to write supervision tree: %w", err)
	}

	ab.Log.Printf("finished building filesystem in %s", ab.WorkDir)
	return nil
}

// Installs the BusyBox symlinks, if appropriate.
func (ab *apkBuilder) InstallBusyboxSymlinks() error {
	path := filepath.Join(ab.WorkDir, "bin", "busybox")

	_, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}

		return err
	}

	// use proot + qemu to run the installer
	if err := ab.executor.ExecuteChroot("/bin/busybox", "--install", "-s"); err != nil {
		return fmt.Errorf("failed to install busybox symlinks: %w", err)
	}

	return nil
}
