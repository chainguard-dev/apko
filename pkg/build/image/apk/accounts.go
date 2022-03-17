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
	"log"
	"path/filepath"

	"golang.org/x/sync/errgroup"

	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/passwd"
)

func appendGroup(groups []passwd.GroupEntry, group types.Group) []passwd.GroupEntry {
	ge := passwd.GroupEntry{
		GroupName: group.GroupName,
		GID:       group.GID,
		Members:   group.Members,
		Password:  "x",
	}
	return append(groups, ge)
}

func appendUser(users []passwd.UserEntry, user types.User) []passwd.UserEntry {
	if user.GID == 0 {
		log.Printf("guessing unset GID for user %v", user)
		user.GID = user.UID
	}

	ue := passwd.UserEntry{
		UserName: user.UserName,
		UID:      user.UID,
		GID:      user.GID,
		HomeDir:  "/home/" + user.UserName,
		Password: "x",
		Info:     "Account created by apko",
		Shell:    "/bin/sh",
	}
	return append(users, ue)
}

func (ab *apkBuilder) MutateAccounts() error {
	ic := ab.ImageConfiguration

	var eg errgroup.Group

	if len(ic.Accounts.Groups) != 0 {
		// Mutate the /etc/groups file
		eg.Go(func() error {
			path := filepath.Join(ab.WorkDir, "etc", "group")

			gf, err := passwd.ReadOrCreateGroupFile(path)
			if err != nil {
				return err
			}

			for _, g := range ic.Accounts.Groups {
				gf.Entries = appendGroup(gf.Entries, g)
			}

			if err := gf.WriteFile(path); err != nil {
				return err
			}

			return nil
		})
	}

	if len(ic.Accounts.Users) != 0 {
		// Mutate the /etc/passwd file
		eg.Go(func() error {
			path := filepath.Join(ab.WorkDir, "etc", "passwd")

			uf, err := passwd.ReadOrCreateUserFile(path)
			if err != nil {
				return err
			}

			for _, u := range ic.Accounts.Users {
				uf.Entries = appendUser(uf.Entries, u)
			}

			if err := uf.WriteFile(path); err != nil {
				return err
			}

			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return err
	}

	return nil
}
