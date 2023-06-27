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
	"os"
	"path/filepath"

	apkfs "github.com/chainguard-dev/go-apk/pkg/fs"
	"golang.org/x/sync/errgroup"

	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/options"
	"chainguard.dev/apko/pkg/passwd"
)

func (di *buildImplementation) appendGroup(
	o *options.Options, groups []passwd.GroupEntry, group types.Group,
) []passwd.GroupEntry {
	o.Logger().Printf("creating group %d(%s)", group.GID, group.GroupName)

	ge := passwd.GroupEntry{
		GroupName: group.GroupName,
		GID:       group.GID,
		Members:   group.Members,
		Password:  "x",
	}

	return append(groups, ge)
}

func userToUserEntry(user types.User) passwd.UserEntry {
	if user.GID == 0 {
		user.GID = user.UID
	}
	return passwd.UserEntry{
		UserName: user.UserName,
		UID:      user.UID,
		GID:      user.GID,
		HomeDir:  "/home/" + user.UserName,
		Password: "x",
		Info:     "Account created by apko",
		Shell:    "/bin/sh",
	}
}

func (di *buildImplementation) MutateAccounts(
	fsys apkfs.FullFS, o *options.Options, ic *types.ImageConfiguration,
) error {
	var eg errgroup.Group

	if len(ic.Accounts.Groups) != 0 {
		// Mutate the /etc/groups file
		eg.Go(func() error {
			path := filepath.Join("etc", "group")

			gf, err := passwd.ReadOrCreateGroupFile(fsys, path)
			if err != nil {
				return err
			}

			for _, g := range ic.Accounts.Groups {
				gf.Entries = di.appendGroup(o, gf.Entries, g)
			}

			if err := gf.WriteFile(fsys, path); err != nil {
				return err
			}

			return nil
		})
	}

	// Mutate the /etc/passwd file
	eg.Go(func() error {
		path := filepath.Join("etc", "passwd")

		uf, err := passwd.ReadOrCreateUserFile(fsys, path)
		if err != nil {
			return err
		}

		for _, u := range ic.Accounts.Users {
			ue := userToUserEntry(u)
			uf.Entries = append(uf.Entries, ue)
		}
		for _, ue := range uf.Entries {
			// This is what the home directory is set to for our homeless users.
			if ue.HomeDir == "/dev/null" {
				continue
			}
			// Create a version of the user's home directory rooted at our
			// working directory.
			targetHomedir := ue.HomeDir

			// Make sure a directory exists with the path we expect.
			if fi, err := fsys.Stat(targetHomedir); err == nil {
				if !fi.IsDir() {
					return fmt.Errorf("%s home directory %s exists, but is not a directory", ue.UserName, ue.HomeDir)
				}
				// If the directory already exists, we do not mess with the
				// permissions because some built-in users use things like:
				//    /bin, /sbin, /
				// and we don't want to screw with those permissions.
				continue
			} else if !os.IsNotExist(err) {
				return fmt.Errorf("checking homedir exists: %w", err)
			}
			// Create the directory. Only the directory should be 0o700; parents, if they are missing, should be 0o755.
			parent := filepath.Dir(targetHomedir)
			if err := fsys.MkdirAll(parent, 0o755); err != nil {
				return fmt.Errorf("creating parent %s: %w", parent, err)
			}
			if err := fsys.Mkdir(targetHomedir, 0o700); err != nil {
				return fmt.Errorf("creating homedir: %w", err)
			}
			if err := fsys.Chown(targetHomedir, int(ue.UID), int(ue.GID)); err != nil {
				return fmt.Errorf("chowning homedir: %w", err)
			}
		}

		if err := uf.WriteFile(path); err != nil {
			return err
		}

		// Resolve run-as user if requested.
		if ic.Accounts.RunAs != "" {
			for _, ue := range uf.Entries {
				if ue.UserName == ic.Accounts.RunAs {
					ic.Accounts.RunAs = fmt.Sprintf("%d", ue.UID)
					break
				}
			}
		}

		return nil
	})

	if err := eg.Wait(); err != nil {
		return err
	}

	return nil
}
