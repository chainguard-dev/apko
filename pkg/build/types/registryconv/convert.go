// Copyright 2026 Chainguard, Inc.
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

// Package registryconv translates apko's image configuration to and from the
// Chainguard Registry API's ApkoConfig message.
package registryconv

import (
	registryv1 "chainguard.dev/sdk/proto/platform/registry/v1"

	apkotypes "chainguard.dev/apko/pkg/build/types"
)

// ToApkoProto converts an apko image configuration to the Registry API's
// ApkoConfig. Include, Format, Contents.BaseImage and Contents.RuntimeKeyring
// have no ApkoConfig counterpart and are dropped.
func ToApkoProto(ic apkotypes.ImageConfiguration) *registryv1.ApkoConfig {
	return &registryv1.ApkoConfig{
		Contents: &registryv1.ApkoConfig_Contents{
			Repositories:        ic.Contents.Repositories,
			BuildRepositories:   ic.Contents.BuildRepositories,
			RuntimeRepositories: ic.Contents.RuntimeOnlyRepositories,
			Keyring:             ic.Contents.Keyring,
			Packages:            ic.Contents.Packages,
		},
		Environment: ic.Environment,
		Accounts: &registryv1.ApkoConfig_Accounts{
			Users:  pbUsers(ic.Accounts.Users),
			Groups: pbGroups(ic.Accounts.Groups),
			RunAs:  ic.Accounts.RunAs,
		},
		Annotations:  ic.Annotations,
		Paths:        pbPaths(ic.Paths),
		Entrypoint:   pbEntrypoint(ic.Entrypoint),
		Cmd:          ic.Cmd,
		WorkDir:      ic.WorkDir,
		Archs:        pbArchs(ic.Archs),
		Layering:     pbLayering(ic.Layering),
		Certificates: pbCertificates(ic.Certificates),

		// These are unused.
		Volumes:    ic.Volumes,
		StopSignal: ic.StopSignal,
		VcsUrl:     ic.VCSUrl,
	}
}

func pbArchs(archs []apkotypes.Architecture) []string {
	if archs == nil {
		return nil
	}
	pbArchs := make([]string, len(archs))
	for i, a := range archs {
		pbArchs[i] = a.String()
	}
	return pbArchs
}

func pbUsers(users []apkotypes.User) []*registryv1.ApkoConfig_Accounts_User {
	if users == nil {
		return nil
	}
	pbUsers := make([]*registryv1.ApkoConfig_Accounts_User, len(users))
	for i, u := range users {
		pbUsers[i] = &registryv1.ApkoConfig_Accounts_User{
			Uid:      u.UID,
			UserName: u.UserName,
			Gid:      u.GID,
			Shell:    u.Shell,
			HomeDir:  u.HomeDir,
		}
	}
	return pbUsers
}

func pbGroups(groups []apkotypes.Group) []*registryv1.ApkoConfig_Accounts_Group {
	if groups == nil {
		return nil
	}
	pbGroups := make([]*registryv1.ApkoConfig_Accounts_Group, len(groups))
	for i, g := range groups {
		pbGroups[i] = &registryv1.ApkoConfig_Accounts_Group{
			Gid:       g.GID,
			GroupName: g.GroupName,
			Members:   g.Members,
		}
	}
	return pbGroups
}

func pbPaths(paths []apkotypes.PathMutation) []*registryv1.ApkoConfig_PathMutation {
	if paths == nil {
		return nil
	}
	pbPaths := make([]*registryv1.ApkoConfig_PathMutation, len(paths))
	for i, p := range paths {
		pbPaths[i] = &registryv1.ApkoConfig_PathMutation{
			Path:        p.Path,
			Type:        p.Type,
			Uid:         p.UID,
			Gid:         p.GID,
			Permissions: p.Permissions,
			Source:      p.Source,
			Recursive:   p.Recursive,
		}
	}
	return pbPaths
}

func pbEntrypoint(entrypoint apkotypes.ImageEntrypoint) *registryv1.ApkoConfig_Entrypoint {
	return &registryv1.ApkoConfig_Entrypoint{
		Type:          entrypoint.Type,
		Command:       entrypoint.Command,
		ShellFragment: entrypoint.ShellFragment,
		Services:      entrypoint.Services,
	}
}

func pbLayering(layering *apkotypes.Layering) *registryv1.ApkoConfig_Layering {
	if layering == nil {
		return nil
	}
	return &registryv1.ApkoConfig_Layering{
		Strategy: layering.Strategy,
		Budget:   int64(layering.Budget),
	}
}

func pbCertificates(certs *apkotypes.ImageCertificates) *registryv1.ApkoConfig_Certificates {
	if certs == nil {
		return nil
	}

	var additional []*registryv1.ApkoConfig_Certificates_AdditionalEntry
	if len(certs.Additional) > 0 {
		additional = make([]*registryv1.ApkoConfig_Certificates_AdditionalEntry, 0, len(certs.Additional))
		for _, cert := range certs.Additional {
			additional = append(additional, &registryv1.ApkoConfig_Certificates_AdditionalEntry{
				Name:    cert.Name,
				Content: cert.Content,
			})
		}
	}
	return &registryv1.ApkoConfig_Certificates{
		Additional: additional,
		Providers:  certs.Providers,
	}
}

// ToApkoNative converts the Registry API's ApkoConfig to an apko image
// configuration. A nil cfg yields the zero ImageConfiguration.
func ToApkoNative(cfg *registryv1.ApkoConfig) apkotypes.ImageConfiguration {
	if cfg == nil {
		return apkotypes.ImageConfiguration{}
	}

	return apkotypes.ImageConfiguration{
		Contents:     apkoContents(cfg.Contents),
		Environment:  cfg.Environment,
		Accounts:     apkoAccounts(cfg.Accounts),
		Annotations:  cfg.Annotations,
		Paths:        apkoPaths(cfg.Paths),
		Entrypoint:   apkoEntrypoint(cfg.Entrypoint),
		Cmd:          cfg.Cmd,
		WorkDir:      cfg.WorkDir,
		Archs:        apkoArchs(cfg.Archs),
		Layering:     apkoLayering(cfg.Layering),
		Certificates: apkoCertificates(cfg.Certificates),

		// These are unused.
		Volumes:    cfg.Volumes,
		StopSignal: cfg.StopSignal,
		VCSUrl:     cfg.VcsUrl,
	}
}

func apkoContents(contents *registryv1.ApkoConfig_Contents) apkotypes.ImageContents {
	if contents == nil {
		return apkotypes.ImageContents{}
	}

	return apkotypes.ImageContents{
		Repositories:            contents.Repositories,
		BuildRepositories:       contents.BuildRepositories,
		RuntimeOnlyRepositories: contents.RuntimeRepositories,
		Keyring:                 contents.Keyring,
		Packages:                contents.Packages,
	}
}

func apkoArchs(archs []string) []apkotypes.Architecture {
	if archs == nil {
		return nil
	}
	apkoArchs := make([]apkotypes.Architecture, len(archs))
	for i, a := range archs {
		apkoArchs[i] = apkotypes.ParseArchitecture(a)
	}
	return apkoArchs
}

func apkoAccounts(accounts *registryv1.ApkoConfig_Accounts) apkotypes.ImageAccounts {
	if accounts == nil {
		return apkotypes.ImageAccounts{}
	}
	return apkotypes.ImageAccounts{
		Users:  apkoUsers(accounts.Users),
		Groups: apkoGroups(accounts.Groups),
		RunAs:  accounts.RunAs,
	}
}

func apkoUsers(users []*registryv1.ApkoConfig_Accounts_User) []apkotypes.User {
	if users == nil {
		return nil
	}
	apkoUsers := make([]apkotypes.User, len(users))
	for i, u := range users {
		apkoUsers[i] = apkotypes.User{
			UID:      u.Uid,
			UserName: u.UserName,
			GID:      u.Gid,
			Shell:    u.Shell,
			HomeDir:  u.HomeDir,
		}
	}
	return apkoUsers
}

func apkoGroups(groups []*registryv1.ApkoConfig_Accounts_Group) []apkotypes.Group {
	if groups == nil {
		return nil
	}
	apkoGroups := make([]apkotypes.Group, len(groups))
	for i, g := range groups {
		apkoGroups[i] = apkotypes.Group{
			GID:       g.Gid,
			GroupName: g.GroupName,
			Members:   g.Members,
		}
	}
	return apkoGroups
}

func apkoPaths(paths []*registryv1.ApkoConfig_PathMutation) []apkotypes.PathMutation {
	if paths == nil {
		return nil
	}
	apkoPaths := make([]apkotypes.PathMutation, len(paths))
	for i, p := range paths {
		apkoPaths[i] = apkotypes.PathMutation{
			Path:        p.Path,
			Type:        p.Type,
			UID:         p.Uid,
			GID:         p.Gid,
			Permissions: p.Permissions,
			Source:      p.Source,
			Recursive:   p.Recursive,
		}
	}
	return apkoPaths
}

func apkoEntrypoint(entrypoint *registryv1.ApkoConfig_Entrypoint) apkotypes.ImageEntrypoint {
	if entrypoint == nil {
		return apkotypes.ImageEntrypoint{}
	}
	return apkotypes.ImageEntrypoint{
		Type:          entrypoint.Type,
		Command:       entrypoint.Command,
		ShellFragment: entrypoint.ShellFragment,
		Services:      entrypoint.Services,
	}
}

func apkoLayering(layering *registryv1.ApkoConfig_Layering) *apkotypes.Layering {
	if layering == nil {
		return nil
	}
	return &apkotypes.Layering{
		Strategy: layering.Strategy,
		Budget:   int(layering.Budget),
	}
}

func apkoCertificates(certs *registryv1.ApkoConfig_Certificates) *apkotypes.ImageCertificates {
	if certs == nil {
		return nil
	}

	var additional []apkotypes.AdditionalCertificateEntry
	if len(certs.Additional) > 0 {
		additional = make([]apkotypes.AdditionalCertificateEntry, 0, len(certs.Additional))
		for _, cert := range certs.Additional {
			additional = append(additional, apkotypes.AdditionalCertificateEntry{
				Name:    cert.Name,
				Content: cert.Content,
			})
		}
	}
	return &apkotypes.ImageCertificates{
		Additional: additional,
		Providers:  certs.Providers,
	}
}
