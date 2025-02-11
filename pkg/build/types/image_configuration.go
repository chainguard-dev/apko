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

package types

import (
	"context"
	"fmt"
	"hash"
	"maps"
	"os"
	"reflect"
	"slices"
	"strings"

	"github.com/google/go-cmp/cmp"
	"gopkg.in/yaml.v3"

	"github.com/chainguard-dev/clog"

	"chainguard.dev/apko/pkg/paths"
	"chainguard.dev/apko/pkg/vcs"
)

// Attempt to probe an upstream VCS URL if known.
func (ic *ImageConfiguration) ProbeVCSUrl(ctx context.Context, imageConfigPath string) {
	log := clog.FromContext(ctx)

	url, err := vcs.ProbeDirFromPath(imageConfigPath)
	if err != nil {
		log.Debugf("failed to probe VCS URL: %v", err)
		return
	}

	if url != "" {
		ic.VCSUrl = url
		log.Debugf("detected %s as VCS URL", ic.VCSUrl)
	}
}

// Parse a configuration blob into an ImageConfiguration struct.
func (ic *ImageConfiguration) parse(ctx context.Context, configData []byte, includePaths []string, configHasher hash.Hash) error {
	log := clog.FromContext(ctx)
	configHasher.Write(configData)
	dec := yaml.NewDecoder(strings.NewReader(string(configData)))
	dec.KnownFields(true)
	if err := dec.Decode(ic); err != nil {
		return fmt.Errorf("failed to parse image configuration: %w", err)
	}

	if ic.Include != "" {
		log.Infof("including %s for configuration", ic.Include)

		included := &ImageConfiguration{}

		if err := included.Load(ctx, ic.Include, includePaths, configHasher); err != nil {
			return fmt.Errorf("failed to read include file: %w", err)
		}

		if err := included.MergeInto(ic); err != nil {
			return fmt.Errorf("failed to merge included configuration: %w", err)
		}
	}

	runtimeRepos := make([]string, 0, len(ic.Contents.RuntimeRepositories))
	for _, repo := range ic.Contents.RuntimeRepositories {
		repo = strings.TrimRight(repo, "/")
		runtimeRepos = append(runtimeRepos, repo)
	}
	ic.Contents.RuntimeRepositories = runtimeRepos

	buildRepos := make([]string, 0, len(ic.Contents.BuildRepositories))
	for _, repo := range ic.Contents.BuildRepositories {
		repo = strings.TrimRight(repo, "/")
		buildRepos = append(buildRepos, repo)
	}
	ic.Contents.BuildRepositories = buildRepos

	// The top level components restriction is on the conservative side. Some of them would probably work out of the box.
	// If someone needs any of them, it should be a matter of testing and hopefully doing minor changes.
	if ic.Contents.BaseImage != nil {
		if !cmp.Equal((ImageEntrypoint{}), ic.Entrypoint) ||
			ic.Cmd != "" ||
			ic.StopSignal != "" ||
			ic.WorkDir != "" ||
			!cmp.Equal((ImageAccounts{}), ic.Accounts) ||
			len(ic.Environment) != 0 ||
			len(ic.Paths) != 0 ||
			len(ic.Annotations) != 0 {
			return fmt.Errorf("when using base image, the only supported image specification are: contents, archs and includes")
		}
	}

	return nil
}

// Merge this configuration into the target, with the target taking precedence.
func (ic *ImageConfiguration) MergeInto(target *ImageConfiguration) error {
	if reflect.ValueOf(target.Entrypoint).IsZero() {
		target.Entrypoint = ic.Entrypoint
	}
	if target.Cmd == "" {
		target.Cmd = ic.Cmd
	}
	if target.StopSignal == "" {
		target.StopSignal = ic.StopSignal
	}
	if target.WorkDir == "" {
		target.WorkDir = ic.WorkDir
	}
	if len(target.Archs) == 0 {
		target.Archs = ic.Archs
	}
	if err := ic.Accounts.MergeInto(&target.Accounts); err != nil {
		return err
	}
	if target.Environment == nil && ic.Environment != nil {
		target.Environment = maps.Clone(ic.Environment)
	} else {
		for k, v := range ic.Environment {
			if _, ok := target.Environment[k]; !ok {
				target.Environment[k] = v
			}
		}
	}
	target.Paths = slices.Concat(ic.Paths, target.Paths)
	if target.Annotations == nil && ic.Annotations != nil {
		target.Annotations = maps.Clone(ic.Annotations)
	} else {
		for k, v := range ic.Annotations {
			if _, ok := target.Annotations[k]; !ok {
				target.Annotations[k] = v
			}
		}
	}

	target.Volumes = slices.Concat(ic.Volumes, target.Volumes)

	// Update the contents.
	return ic.Contents.MergeInto(&target.Contents)
}

func (a *ImageAccounts) MergeInto(target *ImageAccounts) error {
	if target.RunAs == "" {
		target.RunAs = a.RunAs
	}
	target.Users = slices.Concat(a.Users, target.Users)
	target.Groups = slices.Concat(a.Groups, target.Groups)
	return nil
}

func (i *ImageContents) MergeInto(target *ImageContents) error {
	target.Keyring = slices.Concat(i.Keyring, target.Keyring)
	target.BuildRepositories = slices.Concat(i.BuildRepositories, target.BuildRepositories)
	target.RuntimeRepositories = slices.Concat(i.RuntimeRepositories, target.RuntimeRepositories)
	target.Packages = slices.Concat(i.Packages, target.Packages)
	return nil
}

func (ic *ImageConfiguration) readLocal(imageconfigPath string, includePaths []string) ([]byte, error) {
	resolvedPath, err := paths.ResolvePath(imageconfigPath, includePaths)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(resolvedPath)
}

// Load - loads an image configuration given a configuration file path.
// Populates configHasher with the configuration data loaded from the imageConfigPath and the other referenced files.
// You can pass any dummy hasher (like fnv.New32()), if you don't care about the hash of the configuration.
//
// Deprecated: This will be removed in a future release.
func (ic *ImageConfiguration) Load(ctx context.Context, imageConfigPath string, includePaths []string, configHasher hash.Hash) error {
	data, err := ic.readLocal(imageConfigPath, includePaths)
	if err != nil {
		return err
	}

	return ic.parse(ctx, data, includePaths, configHasher)
}

// Do preflight checks and mutations on an image configuration.
func (ic *ImageConfiguration) Validate() error {
	if ic.Entrypoint.Type == "service-bundle" {
		if err := ic.ValidateServiceBundle(); err != nil {
			return err
		}
	}

	for i, u := range ic.Accounts.Users {
		if u.UserName == "" {
			return fmt.Errorf("configured user %v has no configured user name", u)
		}

		if u.UID == 0 {
			return fmt.Errorf("configured user %v has UID 0 (to run as root, use `run-as: 0`)", u)
		}

		if u.HomeDir == "" {
			ic.Accounts.Users[i].HomeDir = "/home/" + u.UserName
		}
	}

	for _, g := range ic.Accounts.Groups {
		if g.GroupName == "" {
			return fmt.Errorf("configured group %v has no configured group name", g)
		}
	}
	return nil
}

// Do preflight checks and mutations on an image configured to manage
// a service bundle.
func (ic *ImageConfiguration) ValidateServiceBundle() error {
	ic.Entrypoint.Command = "/bin/s6-svscan /sv"

	// It's harmless to have a duplicate entry in /etc/apk/world,
	// apk will fix it up when the fixate op happens.
	ic.Contents.Packages = append(ic.Contents.Packages, "s6")

	return nil
}

func (ic *ImageConfiguration) Summarize(ctx context.Context) {
	log := clog.FromContext(ctx)

	log.Infof("image configuration:")
	log.Infof("  contents:")
	log.Infof("    build repositories: %v", ic.Contents.BuildRepositories)
	log.Infof("    runtime repositories: %v", ic.Contents.RuntimeRepositories)
	log.Infof("    keyring:      %v", ic.Contents.Keyring)
	log.Infof("    packages:     %v", ic.Contents.Packages)
	if ic.Entrypoint.Type != "" || ic.Entrypoint.Command != "" || len(ic.Entrypoint.Services) != 0 {
		log.Infof("  entrypoint:")
		log.Infof("    type:    %s", ic.Entrypoint.Type)
		log.Infof("    command:     %s", ic.Entrypoint.Command)
		log.Infof("    service: %v", ic.Entrypoint.Services)
		log.Infof("    shell fragment: %v", ic.Entrypoint.ShellFragment)
	}
	if ic.Cmd != "" {
		log.Infof("  cmd: %s", ic.Cmd)
	}
	if ic.StopSignal != "" {
		log.Infof("  stop signal: %s", ic.StopSignal)
	}

	if ic.Accounts.RunAs != "" || len(ic.Accounts.Users) != 0 || len(ic.Accounts.Groups) != 0 {
		log.Infof("  accounts:")
		log.Infof("    runas:  %s", ic.Accounts.RunAs)
		log.Infof("    users:")
		for _, u := range ic.Accounts.Users {
			log.Infof("      - uid=%d(%s) gid=%d", u.UID, u.UserName, gidToInt(u.GID))
		}
		log.Infof("    groups:")
		for _, g := range ic.Accounts.Groups {
			log.Infof("      - gid=%d(%s) members=%v", g.GID, g.GroupName, g.Members)
		}
	}
	if len(ic.Annotations) > 0 {
		log.Infof("    annotations:")
		for k, v := range ic.Annotations {
			log.Infof("      %s: %s", k, v)
		}
	}
}

func gidToInt(gid GID) uint32 {
	if gid == nil {
		return 0
	}
	return *gid
}
