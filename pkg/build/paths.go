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
	o.Logger().Debugf("[DEBUG] [paths.go] Target Caps %v on %v", targetCaps, target)

	targetCapString := strings.Join(targetCaps, ",")
	currentSet, err := cap.GetFile(target)
	if err != nil {
		o.Logger().Debugf("[ERROR] cap.GetFile(target) %v", err)
		if err.Error() == "no data available" {
			currentSet = &cap.Set{}
		} else {
			return err
		}
	}
	targetSet, err := cap.FromText(targetCapString)
	if err != nil {
		o.Logger().Errorf("[ERROR] cap.FromText(targetCapString) %v", err)
		return err
	}
	o.Logger().Debugf("[INFO] Current Set caps %v", currentSet.String())
	o.Logger().Debugf("[INFO] Target Set caps %v", targetSet.String())

	file, err := os.Open(target)
	if err != nil {
		o.Logger().Errorf("[ERROR] opening target %v", err)
		return err
	}

	if err := targetSet.SetFd(file); err != nil {
		o.Logger().Errorf("[ERROR] Error setting caps with SetFd on file %v %v", target, err)
		return err
	}

	if err := file.Sync(); err != nil {
		o.Logger().Errorf("[ERROR] Error Syncing file target %v %v", target, err)
		return err
	}

	defer file.Close()

	currentSet, err = cap.GetFile(target)
	if err != nil {
		o.Logger().Debugf("[ERROR] cap.GetFile(target) %v", err)
		o.Logger().Debugf("[ERROR] Error Syncing file target %v %v", target, err)
		return err
	} else {
		o.Logger().Debugf("[INFO] Current Set caps After setting %v", currentSet.String())
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
				o.Logger().Debugf("[ERROR] paths.go cap.GetFile(target) %v", err)
			} else {
				o.Logger().Debugf("[INFO] paths.go current set after return %v", currentSet.String())
			}
			mutSet, err := cap.GetFile(mut.Path)
			if err != nil {
				o.Logger().Debugf("[ERROR] paths.go mutSet %v", err)
			} else {
				o.Logger().Debugf("[INFO] paths.go mutSet set after return %v", mutSet.String())
			}
		}
	}

	return nil
}
