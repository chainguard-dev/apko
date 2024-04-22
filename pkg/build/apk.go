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
	"context"
	"fmt"
	"regexp"

	"go.opentelemetry.io/otel"
	"golang.org/x/sync/errgroup"
	"k8s.io/apimachinery/pkg/util/sets"
)

func (bc *Context) postBuildSetApk(ctx context.Context) error {
	if bc.baseimg == nil {
		return nil
	}
	// When building on top of base image, we add "artificial" apkindex to repositories that is
	// stored in some temp path. After build is done we need to bring the repositories file to
	// clean state so that image builds are byte identical.
	repos := sets.List(sets.New(bc.ic.Contents.Repositories...).Insert(bc.o.ExtraRepos...))
	if err := bc.apk.SetRepositories(ctx, repos); err != nil {
		return fmt.Errorf("failed to set apk repositories: %w", err)
	}
	// TODO(sfc-gh-mhazy) Handle the rest of apk files (scripts, triggers)
	return nil
}

func (bc *Context) initializeApk(ctx context.Context) error {
	ctx, span := otel.Tracer("apko").Start(ctx, "iniializeApk")
	defer span.End()

	alpineVersions := parseOptionsFromRepositories(bc.ic.Contents.Repositories)
	if err := bc.apk.InitDB(ctx, alpineVersions...); err != nil {
		return fmt.Errorf("failed to initialize apk database: %w", err)
	}

	var eg errgroup.Group

	eg.Go(func() error {
		keyring := sets.List(sets.New(bc.ic.Contents.Keyring...).Insert(bc.o.ExtraKeyFiles...))
		if err := bc.apk.InitKeyring(ctx, keyring, nil); err != nil {
			return fmt.Errorf("failed to initialize apk keyring: %w", err)
		}
		return nil
	})

	eg.Go(func() error {
		repos := sets.List(sets.New(bc.ic.Contents.Repositories...).Insert(bc.o.ExtraRepos...))
		// We add auxiliary repository to resolve packages from the base image.
		if bc.baseimg != nil {
			repos = append(repos, bc.baseimg.APKIndexPath())
		}
		if err := bc.apk.SetRepositories(ctx, repos); err != nil {
			return fmt.Errorf("failed to initialize apk repositories: %w", err)
		}
		return nil
	})

	eg.Go(func() error {
		packages := sets.List(sets.New(bc.ic.Contents.Packages...).Insert(bc.o.ExtraPackages...))
		// Get all packages from base image and merge them into the desired world.
		if bc.baseimg != nil {
			basePkgs := bc.baseimg.InstalledPackages()
			var basePkgsNames []string
			for _, basePkg := range basePkgs {
				basePkgsNames = append(basePkgsNames, fmt.Sprintf("%s=%s", basePkg.Package.Name, basePkg.Package.Version))
			}
			packages = append(packages, basePkgsNames...)
		}
		if err := bc.apk.SetWorld(ctx, packages); err != nil {
			return fmt.Errorf("failed to initialize apk world: %w", err)
		}
		return nil
	})

	if err := eg.Wait(); err != nil {
		return err
	}

	return nil
}

var repoRE = regexp.MustCompile(`^http[s]?://.+\/alpine\/([^\/]+)\/[^\/]+$`)

func parseOptionsFromRepositories(repos []string) []string {
	var versions = make([]string, 0)
	for _, r := range repos {
		parts := repoRE.FindStringSubmatch(r)
		if len(parts) < 2 {
			continue
		}
		versions = append(versions, parts[1])
	}
	return versions
}
