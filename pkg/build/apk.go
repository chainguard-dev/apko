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
	"compress/gzip"
	"context"
	"fmt"
	"os"
	"regexp"

	"golang.org/x/sync/errgroup"
	"k8s.io/apimachinery/pkg/util/sets"
)

func (bc *Context) initializeApk(ctx context.Context) error {
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
		// TODO cleanup or store outside workdir?
		if bc.baseimg != nil {
			// TODO nie os
			if err := os.Mkdir("test_dir", 0777); err != nil {
				return err
			}
			// TODO nie os
			if err := os.Mkdir("test_dir/"+bc.Arch().ToAPK(), 0777); err != nil {
				return err
			}
			// TODO nie os
			TarFile, err := os.OpenFile("test_dir/"+bc.Arch().ToAPK()+"/APKINDEX.tar.gz", os.O_CREATE|os.O_WRONLY, 0777)
			if err != nil {
				return err
			}
			defer TarFile.Close()
			gzipwriter := gzip.NewWriter(TarFile)
			defer gzipwriter.Close()
			tarWriter := tar.NewWriter(gzipwriter)
			defer tarWriter.Close()
			header := tar.Header{Name: "APKINDEX", Size: int64(len(bc.baseimg.apkIndex)), Mode: 0777}
			if err := tarWriter.WriteHeader(&header); err != nil {
				return err
			}
			if _, err := tarWriter.Write(bc.baseimg.apkIndex); err != nil {
				return err
			}

			repos = append(repos, "./test_dir")
		}
		if err := bc.apk.SetRepositories(ctx, repos); err != nil {
			return fmt.Errorf("failed to initialize apk repositories: %w", err)
		}
		return nil
	})

	eg.Go(func() error {
		packages := sets.List(sets.New(bc.ic.Contents.Packages...).Insert(bc.o.ExtraPackages...))
		if bc.baseimg != nil {
			basepackages, err := bc.baseimg.Packages()
			if err != nil {
				return err
			}
			packages = append(packages, basepackages...)
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
