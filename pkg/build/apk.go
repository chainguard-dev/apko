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

	"go.opentelemetry.io/otel"
	"golang.org/x/sync/errgroup"
	"k8s.io/apimachinery/pkg/util/sets"
)

func (bc *Context) postBuildSetApk(ctx context.Context) error {
	// When building on top of base image, we add "artificial" apkindex to repositories that is
	// stored in some temp path. After build is done we need to bring the repositories file to
	// clean state so that image builds are byte identical.
	//
	// We do not include the build-time repositories here, because this is
	// what defines the /etc/apk/repositories file in the final image.
	runtimeRepos := sets.List(sets.New(bc.ic.Contents.RuntimeRepositories...).Insert(bc.o.ExtraRuntimeRepos...))
	if err := bc.apk.SetRepositories(ctx, runtimeRepos); err != nil {
		return fmt.Errorf("failed to set apk repositories: %w", err)
	}
	// TODO(sfc-gh-mhazy) Handle the rest of apk files (scripts, triggers)
	return nil
}

func (bc *Context) initializeApk(ctx context.Context) error {
	ctx, span := otel.Tracer("apko").Start(ctx, "initializeApk")
	defer span.End()

	// We set the repositories file to be the union of all of the
	// repositories when we initialize things, and we overwrite it
	// with just the runtime repositories when we are done.
	buildRepos := sets.List(
		sets.New(bc.ic.Contents.BuildRepositories...).
			Insert(bc.ic.Contents.RuntimeRepositories...).
			Insert(bc.o.ExtraBuildRepos...).
			Insert(bc.o.ExtraRuntimeRepos...),
	)
	if err := bc.apk.InitDB(ctx, buildRepos...); err != nil {
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
		// We add auxiliary repository to resolve packages from the base image.
		if bc.baseimg != nil {
			buildRepos = append(buildRepos, bc.baseimg.APKIndexPath())
		}
		if err := bc.apk.SetRepositories(ctx, buildRepos); err != nil {
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
				basePkgsNames = append(basePkgsNames, fmt.Sprintf("%s=%s", basePkg.Name, basePkg.Version))
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
