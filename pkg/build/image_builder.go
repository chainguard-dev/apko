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

package build

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sync/errgroup"

	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/exec"
	"chainguard.dev/apko/pkg/s6"
)

func (di *defaultBuildImplementation) ValidateImageConfiguration(ic *types.ImageConfiguration) error {
	if err := ic.Validate(); err != nil {
		return fmt.Errorf("failed to validate configuration: %w", err)
	}
	return nil
}

// Builds the image in Context.WorkDir.
func (di *defaultBuildImplementation) InitializeApk(o *Options, ic *types.ImageConfiguration, e *exec.Executor) error {
	// initialize apk
	if err := di.InitApkDB(o, e); err != nil {
		return fmt.Errorf("failed to initialize apk database: %w", err)
	}

	var eg errgroup.Group

	eg.Go(func() error {
		if err := di.InitApkKeyring(o, ic); err != nil {
			return fmt.Errorf("failed to initialize apk keyring: %w", err)
		}
		return nil
	})

	eg.Go(func() error {
		if err := di.InitApkRepositories(o, ic); err != nil {
			return fmt.Errorf("failed to initialize apk repositories: %w", err)
		}
		return nil
	})

	eg.Go(func() error {
		if err := di.InitApkWorld(o, ic); err != nil {
			return fmt.Errorf("failed to initialize apk world: %w", err)
		}
		return nil
	})

	if err := eg.Wait(); err != nil {
		return err
	}

	// sync reality with desired apk world
	if err := di.FixateApkWorld(o, e); err != nil {
		return fmt.Errorf("failed to fixate apk world: %w", err)
	}

	eg.Go(func() error {
		if err := di.NormalizeApkScriptsTar(o); err != nil {
			return fmt.Errorf("failed to normalize scripts.tar: %w", err)
		}
		return nil
	})

	if err := eg.Wait(); err != nil {
		return err
	}

	return nil
}

func (di *defaultBuildImplementation) WriteSupervisionTree(
	s6context *s6.Context, imageConfig *types.ImageConfiguration,
) error {
	// write service supervision tree
	if err := s6context.WriteSupervisionTree(imageConfig.Entrypoint.Services); err != nil {
		return fmt.Errorf("failed to write supervision tree: %w", err)
	}
	return nil
}

// Installs the BusyBox symlinks, if appropriate.
func (di *defaultBuildImplementation) InstallBusyboxSymlinks(o *Options, e *exec.Executor) error {
	path := filepath.Join(o.WorkDir, "bin", "busybox")

	_, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}

		return err
	}

	// use proot + qemu to run the installer
	if err := e.ExecuteChroot("/bin/busybox", "--install", "-s"); err != nil {
		return fmt.Errorf("failed to install busybox symlinks: %w", err)
	}

	return nil
}
