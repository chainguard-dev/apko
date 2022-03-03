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
	"path/filepath"

	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/passwd"
	"golang.org/x/sync/errgroup"
)

func appendGroup(groups []passwd.GroupEntry, group types.Group) []passwd.GroupEntry {
	ge := passwd.GroupEntry{
		GroupName: group.GroupName,
		GID: group.GID,
		Members: group.Members,
		Password: "x",
	}
	return append(groups, ge)
}

func appendUser(users []passwd.UserEntry, user types.User) []passwd.UserEntry {
	ue := passwd.UserEntry{
		UserName: user.UserName,
		UID: user.UID,
		GID: user.GID,
		HomeDir: filepath.Join("/home", user.UserName),
		Password: "x",
		Info: "Account created by apko",
		Shell: "/bin/sh",
	}
	return append(users, ue)
}

func (bc *Context) MutateAccounts() error {
	ic := bc.ImageConfiguration

	var eg errgroup.Group

	// Mutate the /etc/groups file
	eg.Go(func() error {
		path := filepath.Join(bc.WorkDir, "/etc/group")

		gf, err := passwd.ReadGroupFile(path)
		if err != nil {
			return err
		}

		for _, g := range ic.Accounts.Groups {
			gf.Entries = appendGroup(gf.Entries, g)
		}

		err = gf.WriteFile(path)
		if err != nil {
			return err
		}

		return nil
	})

	// Mutate the /etc/passwd file
	eg.Go(func() error {
		path := filepath.Join(bc.WorkDir, "/etc/passwd")

		uf, err := passwd.ReadUserFile(path)
		if err != nil {
			return err
		}

		for _, u := range ic.Accounts.Users {
			uf.Entries = appendUser(uf.Entries, u)
		}

		err = uf.WriteFile(path)
		if err != nil {
			return err
		}

		return nil
	})

	if err := eg.Wait(); err != nil {
		return err
	}

	return nil
}
