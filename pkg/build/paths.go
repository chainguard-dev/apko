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
	"archive/tar"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/options"
)

type PathMutator func(*options.Options, types.PathMutation) ([]tar.Header, error)

var pathMutators = map[string]PathMutator{
	"directory":   mutateDirectory,
	"empty-file":  mutateEmptyFile,
	"hardlink":    mutateHardLink,
	"symlink":     mutateSymLink,
	"permissions": mutatePermissions,
}

func mutatePermissions(o *options.Options, mut types.PathMutation) ([]tar.Header, error) {
	return mutatePermissionsDirect(o.WorkDir, mut.Path, mut.Permissions, mut.UID, mut.GID)
}

func mutatePermissionsDirect(workdir, path string, perms, uid, gid uint32) ([]tar.Header, error) {
	target := filepath.Join(workdir, path)

	err1 := os.Chmod(target, fs.FileMode(perms))
	err2 := os.Chown(target, int(uid), int(gid))
	if err1 == nil && err2 == nil {
		return nil, nil
	}

	// we had errors, so we need override info
	return []tar.Header{
		{Name: path, Mode: int64(perms), Uid: int(uid), Gid: int(gid)},
	}, nil
}

func mutateDirectory(o *options.Options, mut types.PathMutation) ([]tar.Header, error) {
	var headers []tar.Header
	perms := fs.FileMode(mut.Permissions)

	if err := os.MkdirAll(filepath.Join(o.WorkDir, mut.Path), perms); err != nil {
		return nil, err
	}

	if mut.Recursive {
		if err := filepath.WalkDir(filepath.Join(o.WorkDir, mut.Path), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			h, err := mutatePermissionsDirect(o.WorkDir, path, mut.Permissions, mut.UID, mut.GID)
			if err != nil {
				headers = append(headers, h...)
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}

	return headers, nil
}

func ensureParentDirectory(o *options.Options, mut types.PathMutation) error {
	target := filepath.Join(o.WorkDir, mut.Path)
	parent := filepath.Dir(target)

	if err := os.MkdirAll(parent, 0755); err != nil {
		return err
	}

	return nil
}

func mutateEmptyFile(o *options.Options, mut types.PathMutation) ([]tar.Header, error) {
	target := filepath.Join(o.WorkDir, mut.Path)

	if err := ensureParentDirectory(o, mut); err != nil {
		return nil, err
	}

	file, err := os.Create(target)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return nil, nil
}

func mutateHardLink(o *options.Options, mut types.PathMutation) ([]tar.Header, error) {
	var headers []tar.Header

	source := filepath.Join(o.WorkDir, mut.Source)
	target := filepath.Join(o.WorkDir, mut.Path)

	if err := ensureParentDirectory(o, mut); err != nil {
		return nil, err
	}

	// overwrite link if already exists
	if _, err := os.Lstat(target); err == nil {
		os.Remove(target)
	}

	if err := os.Link(source, target); err != nil {
		// what if hardlinking is not supported?
		headers = append(headers, tar.Header{
			Typeflag: tar.TypeLink,
			Name:     mut.Path,
			Linkname: mut.Source,
		})
	}

	return headers, nil
}

func mutateSymLink(o *options.Options, mut types.PathMutation) ([]tar.Header, error) {
	var headers []tar.Header

	target := filepath.Join(o.WorkDir, mut.Path)

	if err := ensureParentDirectory(o, mut); err != nil {
		return nil, err
	}

	if err := os.Symlink(mut.Source, target); err != nil {
		// what if symlinking is not supported?
		headers = append(headers, tar.Header{
			Typeflag: tar.TypeSymlink,
			Name:     mut.Path,
			Linkname: mut.Source,
			Uid:      int(mut.UID),
			Gid:      int(mut.GID),
		})
	}

	return headers, nil
}

func (di *defaultBuildImplementation) MutatePaths(
	o *options.Options, ic *types.ImageConfiguration,
) ([]tar.Header, error) {
	var headers []tar.Header
	for _, mut := range ic.Paths {
		pm, ok := pathMutators[mut.Type]
		if !ok {
			return nil, fmt.Errorf("unsupported path mutation type %q", mut.Type)
		}

		h, err := pm(o, mut)
		if err != nil {
			return nil, err
		}
		headers = append(headers, h...)

		if mut.Type != "permissions" {
			h, err := mutatePermissions(o, mut)
			if err != nil {
				return nil, err
			}
			headers = append(headers, h...)
		}
	}

	return headers, nil
}
