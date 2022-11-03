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
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	types "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/options"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

type PathMutator func(*options.Options, types.PathMutation) error

var pathMutators = map[string]PathMutator{
	"directory":    mutateDirectory,
	"empty-file":   mutateEmptyFile,
	"hardlink":     mutateHardLink,
	"symlink":      mutateSymLink,
	"permissions":  mutatePermissions,
	"capabilities": mutateCapabilities,
}

func mutateCapabilities(o *options.Options, mut types.PathMutation) error {

	target := filepath.Join(o.WorkDir, mut.Path)
	targetCaps := mut.Capabilities
	o.Logger().Infof("[DEBUG] [paths.go] Target Caps %v on %v\n", targetCaps, target)

	targetCapString := strings.Join(targetCaps, ",")
	currentSet, err := cap.GetFile(target)
	if err != nil {
		fmt.Printf("[ERROR] cap.GetFile(target) %v\n", err)
		if err.Error() == "no data available" {
			currentSet = &cap.Set{}
		} else {
			return err
		}
	}
	targetSet, err := cap.FromText(targetCapString)
	if err != nil {
		fmt.Printf("[ERROR] cap.FromText(targetCapString) %v\n", err)
		return err
	}
	fmt.Printf("[INFO] Current Set caps %v\n", currentSet.String())
	fmt.Printf("[INFO] Target Set caps %v\n", targetSet.String())

	file, err := os.Open(target)
	if err != nil {
		fmt.Printf("[ERROR] opening target %v\n", err)
		return err
	}

	if err := targetSet.SetFd(file); err != nil {
		fmt.Printf("[ERROR] Error setting caps with SetFd on file %v %v\n", target, err)
		return err
	}

	if err := file.Sync(); err != nil {
		fmt.Printf("[ERROR] Error Syncing file target %v %v\n", target, err)
		return err
	}

	defer file.Close()

	currentSet, err = cap.GetFile(target)
	if err != nil {
		fmt.Printf("[ERROR] cap.GetFile(target) %v\n", err)
		fmt.Printf("[ERROR] Error Syncing file target %v %v\n", target, err)
		return err
	} else {
		fmt.Printf("[INFO] Current Set caps After setting %v\n", currentSet.String())
		return nil
	}
}

func mutatePermissions(o *options.Options, mut types.PathMutation) error {
	target := filepath.Join(o.WorkDir, mut.Path)
	perms := fs.FileMode(mut.Permissions)

	if err := os.Chmod(target, perms); err != nil {
		return err
	}

	if err := os.Chown(target, int(mut.UID), int(mut.GID)); err != nil {
		return err
	}

	return nil
}

func mutateDirectory(o *options.Options, mut types.PathMutation) error {
	perms := fs.FileMode(mut.Permissions)

	if err := os.MkdirAll(filepath.Join(o.WorkDir, mut.Path), perms); err != nil {
		return err
	}

	if mut.Recursive {
		if err := filepath.WalkDir(filepath.Join(o.WorkDir, mut.Path), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if err := os.Chmod(path, perms); err != nil {
				return err
			}
			if err := os.Chown(path, int(mut.UID), int(mut.GID)); err != nil {
				return err
			}
			return nil
		}); err != nil {
			return err
		}
	}

	return nil
}

func ensureParentDirectory(o *options.Options, mut types.PathMutation) error {
	target := filepath.Join(o.WorkDir, mut.Path)
	parent := filepath.Dir(target)

	if err := os.MkdirAll(parent, 0755); err != nil {
		return err
	}

	return nil
}

func mutateEmptyFile(o *options.Options, mut types.PathMutation) error {
	target := filepath.Join(o.WorkDir, mut.Path)

	if err := ensureParentDirectory(o, mut); err != nil {
		return err
	}

	file, err := os.Create(target)
	if err != nil {
		return err
	}
	defer file.Close()

	return nil
}

func mutateHardLink(o *options.Options, mut types.PathMutation) error {
	source := filepath.Join(o.WorkDir, mut.Source)
	target := filepath.Join(o.WorkDir, mut.Path)
	if err := ensureParentDirectory(o, mut); err != nil {
		return err
	}

	if err := os.Link(source, target); err != nil {
		return err
	}

	return nil
}

func mutateSymLink(o *options.Options, mut types.PathMutation) error {

	target := filepath.Join(o.WorkDir, mut.Path)

	if err := ensureParentDirectory(o, mut); err != nil {
		return err
	}

	if err := os.Symlink(mut.Source, target); err != nil {
		return err
	}

	return nil
}

func (di *defaultBuildImplementation) MutatePaths(
	o *options.Options, ic *types.ImageConfiguration,
) error {
	for _, mut := range ic.Paths {
		pm, ok := pathMutators[mut.Type]
		if !ok {
			return fmt.Errorf("unsupported path mutation type %q", mut.Type)
		}

		if err := pm(o, mut); err != nil {
			return err
		}

		if mut.Type != "permissions" {
			if err := mutatePermissions(o, mut); err != nil {
				return err
			}
		}
		if mut.Path == "nginx-ingress-controller" {
			target := filepath.Join(o.WorkDir, mut.Path)
			currentSet, err := cap.GetFile(target)
			if err != nil {
				fmt.Printf("[ERROR] paths.go cap.GetFile(target) %v\n", err)
			} else {
				fmt.Printf("[INFO] paths.go current set after return %v", currentSet.String())
			}
			mutSet, err := cap.GetFile(mut.Path)
			if err != nil {
				fmt.Printf("[ERROR] paths.go mutSet %v\n", err)
			} else {
				fmt.Printf("[INFO] paths.go mutSet set after return %v", mutSet.String())
			}
		}
	}

	return nil
}
