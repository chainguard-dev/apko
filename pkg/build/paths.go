// Copyright 2022, 2023 Chainguard, Inc.
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
	"path/filepath"

	apkfs "github.com/chainguard-dev/go-apk/pkg/fs"

	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/options"
)

type PathMutator func(apkfs.FullFS, *options.Options, types.PathMutation) error

var pathMutators = map[string]PathMutator{
	"directory":   mutateDirectory,
	"empty-file":  mutateEmptyFile,
	"hardlink":    mutateHardLink,
	"symlink":     mutateSymLink,
	"permissions": mutatePermissions,
}

func mutatePermissions(fsys apkfs.FullFS, o *options.Options, mut types.PathMutation) error {
	return mutatePermissionsDirect(fsys, mut.Path, mut.Permissions, mut.UID, mut.GID)
}

func mutatePermissionsDirect(fsys apkfs.FullFS, path string, perms, uid, gid uint32) error {
	target := path

	if err := fsys.Chmod(target, fs.FileMode(perms)); err != nil {
		return err
	}
	if err := fsys.Chown(target, int(uid), int(gid)); err != nil {
		return err
	}
	return nil
}

func mutateDirectory(fsys apkfs.FullFS, o *options.Options, mut types.PathMutation) error {
	perms := fs.FileMode(mut.Permissions)

	if err := fsys.MkdirAll(mut.Path, perms); err != nil {
		return err
	}

	if mut.Recursive {
		if err := fs.WalkDir(fsys, mut.Path, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if err := mutatePermissionsDirect(fsys, path, mut.Permissions, mut.UID, mut.GID); err != nil {
				return err
			}
			return nil
		}); err != nil {
			return err
		}
	}

	return nil
}

func ensureParentDirectory(fsys apkfs.FullFS, mut types.PathMutation) error {
	target := mut.Path
	parent := filepath.Dir(target)

	if err := fsys.MkdirAll(parent, 0755); err != nil {
		return err
	}

	return nil
}

func mutateEmptyFile(fsys apkfs.FullFS, o *options.Options, mut types.PathMutation) error {
	target := mut.Path

	if err := ensureParentDirectory(fsys, mut); err != nil {
		return err
	}

	file, err := fsys.Create(target)
	if err != nil {
		return err
	}
	defer file.Close()

	return nil
}

func mutateHardLink(fsys apkfs.FullFS, o *options.Options, mut types.PathMutation) error {
	source := mut.Source
	target := mut.Path

	if err := ensureParentDirectory(fsys, mut); err != nil {
		return err
	}

	// overwrite link if already exists
	if _, err := fsys.Lstat(target); err == nil {
		if err := fsys.Remove(target); err != nil {
			return fmt.Errorf("unable to remove old link: %w", err)
		}
	}

	if err := fsys.Link(source, target); err != nil {
		return err
	}

	return nil
}

func mutateSymLink(fsys apkfs.FullFS, o *options.Options, mut types.PathMutation) error {
	target := mut.Path

	if err := ensureParentDirectory(fsys, mut); err != nil {
		return err
	}

	if err := fsys.Symlink(mut.Source, target); err != nil {
		return err
	}

	return nil
}

func (di *buildImplementation) MutatePaths(
	fsys apkfs.FullFS, o *options.Options, ic *types.ImageConfiguration,
) error {
	for _, mut := range ic.Paths {
		pm, ok := pathMutators[mut.Type]
		if !ok {
			return fmt.Errorf("unsupported path mutation type %q", mut.Type)
		}

		if err := pm(fsys, o, mut); err != nil {
			return err
		}

		if mut.Type != "permissions" {
			if err := mutatePermissions(fsys, o, mut); err != nil {
				return err
			}
		}
	}

	return nil
}
