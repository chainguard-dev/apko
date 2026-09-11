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
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"

	apkfs "chainguard.dev/apko/pkg/apk/fs"

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
	if mut.Recursive {
		return mutatePermissionsRecursive(fsys, mut.Path, mut.Permissions, mut.UID, mut.GID)
	}
	return mutatePermissionsDirect(fsys, mut.Path, mut.Permissions, mut.UID, mut.GID)
}

// mutatePermissionsRecursive applies perms (and uid/gid, when set) to path and,
// if path is a directory, to every entry beneath it. WalkDir does not follow
// symlinks, so a symlink entry is mutated in place rather than its target's
// tree being descended.
func mutatePermissionsRecursive(fsys apkfs.FullFS, path string, perms uint32, uid types.UID, gid types.GID) error {
	return fs.WalkDir(fsys, path, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := mutatePermissionsDirect(fsys, p, perms, uid, gid); err != nil {
			return fmt.Errorf("mutating permissions for path %q: %w", p, err)
		}
		return nil
	})
}

// unixModeToFsMode converts raw unix permission bits (as written in apko
// configs, e.g. 0o2775) to fs.FileMode, mapping setuid/setgid/sticky to
// their Go fs.FileMode equivalents.
func unixModeToFsMode(perms uint32) fs.FileMode {
	mode := fs.FileMode(perms & 0o777)
	if perms&0o4000 != 0 {
		mode |= fs.ModeSetuid
	}
	if perms&0o2000 != 0 {
		mode |= fs.ModeSetgid
	}
	if perms&0o1000 != 0 {
		mode |= fs.ModeSticky
	}
	return mode
}

func mutatePermissionsDirect(fsys apkfs.FullFS, path string, perms uint32, uid types.UID, gid types.GID) error {
	target := path

	if err := fsys.Chmod(target, unixModeToFsMode(perms)); err != nil {
		return fmt.Errorf("chmod %q: %w", target, err)
	}

	// Only chown when at least one of uid/gid is set. Omitting both leaves
	// ownership untouched (mode-only), which is what makes a recursive
	// "permissions" mutation safe to run over a pre-existing tree. When only
	// one of the two is set, the other defaults to 0 (root), preserving the
	// historical single-path behavior.
	if uid == nil && gid == nil {
		return nil
	}
	u, g := uint32(0), uint32(0)
	if uid != nil {
		u = *uid
	}
	if gid != nil {
		g = *gid
	}
	if err := fsys.Chown(target, int(u), int(g)); err != nil {
		return fmt.Errorf("chown %q: %w", target, err)
	}
	return nil
}

// mutateDirectory creates the directory tree. Applying the requested
// permissions and ownership (recursively, when mut.Recursive is set) is left to
// the mutatePermissions follow-up that mutatePaths runs for every non-permissions
// mutation, so the recursive walk lives in exactly one place.
func mutateDirectory(fsys apkfs.FullFS, o *options.Options, mut types.PathMutation) error {
	return fsys.MkdirAll(mut.Path, unixModeToFsMode(mut.Permissions))
}

func ensureParentDirectory(fsys apkfs.FullFS, path string) error {
	return fsys.MkdirAll(filepath.Dir(path), 0755)
}

func mutateEmptyFile(fsys apkfs.FullFS, o *options.Options, mut types.PathMutation) error {
	target := mut.Path

	if err := ensureParentDirectory(fsys, target); err != nil {
		return fmt.Errorf("ensuring parent directory for %q: %w", target, err)
	}

	file, err := fsys.Create(target)
	if err != nil {
		return fmt.Errorf("creating file %q: %w", target, err)
	}
	defer file.Close()

	return nil
}

func mutateHardLink(fsys apkfs.FullFS, o *options.Options, mut types.PathMutation) error {
	source := mut.Source
	target := mut.Path

	if err := ensureParentDirectory(fsys, target); err != nil {
		return fmt.Errorf("ensuring parent directory for %q: %w", target, err)
	}

	// overwrite link if already exists
	if _, err := fsys.Lstat(target); err == nil {
		if err := fsys.Remove(target); err != nil {
			return fmt.Errorf("unable to remove old link %q: %w", target, err)
		}
	}

	if err := fsys.Link(source, target); err != nil {
		return fmt.Errorf("linking %q -> %q: %w", source, target, err)
	}

	return nil
}

func mutateSymLink(fsys apkfs.FullFS, o *options.Options, mut types.PathMutation) error {
	target := mut.Path

	if err := ensureParentDirectory(fsys, target); err != nil {
		return fmt.Errorf("ensuring parent directory for %q: %w", target, err)
	}

	if err := fsys.Symlink(mut.Source, target); err != nil {
		return fmt.Errorf("symlinking %q -> %q: %w", mut.Source, target, err)
	}

	return nil
}

func mutatePaths(fsys apkfs.FullFS, o *options.Options, ic *types.ImageConfiguration) error {
	for _, mut := range ic.Paths {
		pm, ok := pathMutators[mut.Type]
		if !ok {
			return fmt.Errorf("unsupported path mutation type %q", mut.Type)
		}

		if err := pm(fsys, o, mut); err != nil {
			if errors.Is(err, fs.ErrExist) {
				err = &PathMutationFileConflictError{Path: mut.Path}
			}
			return fmt.Errorf("mutating path %q: %w", mut.Path, err)
		}

		if mut.Type != "permissions" {
			if err := mutatePermissions(fsys, o, mut); err != nil {
				return fmt.Errorf("%s mutation on %s: %w", mut.Type, mut.Path, err)
			}
		}
	}

	return nil
}

// PathMutationFileConflictError is returned when a path mutation
// attempts to create a file that conflicts with an existing file.
// This is a user error in the image configuration.
type PathMutationFileConflictError struct {
	// The full path of the file that has a conflict.
	Path string
}

func (e *PathMutationFileConflictError) Error() string {
	return fmt.Sprintf("file %q already exists", e.Path)
}
