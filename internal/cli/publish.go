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

package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/chainguard-dev/clog"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/authn/github"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel"
	"golang.org/x/sync/errgroup"

	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/build/oci"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/sbom"
)

func publish() *cobra.Command {
	var imageRefs string
	var buildDate string
	var sbomPath string
	var sbomFormats []string
	var archstrs []string
	var extraKeys []string
	var extraRepos []string
	var extraPackages []string
	var rawAnnotations []string
	var withVCS bool
	var writeSBOM bool
	var local bool
	var cacheDir string
	var offline bool

	cmd := &cobra.Command{
		Use:   "publish <config.yaml> <tag...>",
		Short: "Build and publish an image",
		Long: `Publish a built image from a YAML configuration file.

It is assumed that you have used "docker login" to store credentials
in a keychain.`,
		Example: `  apko publish hello-world.yaml hello:v1.0.0`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 2 {
				return fmt.Errorf("requires at least 2 arg(s), 1 config file and at least 1 tag for the image")
			}

			if !writeSBOM {
				sbomFormats = []string{}
			}
			archs := types.ParseArchitectures(archstrs)
			annotations, err := parseAnnotations(rawAnnotations)
			if err != nil {
				return fmt.Errorf("parsing annotations from command line: %w", err)
			}

			keychain := authn.NewMultiKeychain(
				authn.DefaultKeychain,
				github.Keychain,
			)
			remoteOpts := []remote.Option{remote.WithAuthFromKeychain(keychain)}

			pusher, err := remote.NewPusher(remoteOpts...)
			if err != nil {
				return err
			}
			remoteOpts = append(remoteOpts, remote.Reuse(pusher))

			puller, err := remote.NewPuller(remoteOpts...)
			if err != nil {
				return err
			}
			remoteOpts = append(remoteOpts, remote.Reuse(puller))

			tmp, err := os.MkdirTemp(os.TempDir(), "apko-temp-*")
			if err != nil {
				return fmt.Errorf("creating tempdir: %w", err)
			}
			defer os.RemoveAll(tmp)

			var user, pass string
			if auth, ok := os.LookupEnv("HTTP_AUTH"); !ok {
				// Fine, no auth.
			} else if parts := strings.SplitN(auth, ":", 4); len(parts) != 4 {
				return fmt.Errorf("HTTP_AUTH must be in the form 'basic:REALM:USERNAME:PASSWORD' (got %d parts)", len(parts))
			} else if parts[0] != "basic" {
				return fmt.Errorf("HTTP_AUTH must be in the form 'basic:REALM:USERNAME:PASSWORD' (got %q for first part)", parts[0])
			} else {
				// NB: parts[1] is the realm, which we ignore.
				user, pass = parts[2], parts[3]
			}

			if err := PublishCmd(cmd.Context(), imageRefs, archs, remoteOpts,
				sbomPath,
				[]build.Option{
					build.WithConfig(args[0]),
					build.WithBuildDate(buildDate),
					build.WithAssertions(build.RequireGroupFile(true), build.RequirePasswdFile(true)),
					build.WithSBOM(sbomPath),
					build.WithSBOMFormats(sbomFormats),
					build.WithExtraKeys(extraKeys),
					build.WithExtraRepos(extraRepos),
					build.WithExtraPackages(extraPackages),
					build.WithTags(args[1:]...),
					build.WithVCS(withVCS),
					build.WithAnnotations(annotations),
					build.WithCacheDir(cacheDir, offline),
					build.WithTempDir(tmp),
					build.WithAuth(user, pass),
				},
				[]PublishOption{
					// these are extra here just for publish; everything before is the same for BuildCmd as PublishCmd
					WithLocal(local),
					WithTags(args[1:]...),
				},
			); err != nil {
				return err
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&withVCS, "vcs", true, "detect and embed VCS URLs")
	cmd.Flags().StringVar(&buildDate, "build-date", "", "date used for the timestamps of the files inside the image")
	cmd.Flags().BoolVar(&writeSBOM, "sbom", true, "generate an SBOM")
	cmd.Flags().StringVar(&sbomPath, "sbom-path", "", "path to write the SBOMs")
	cmd.Flags().StringSliceVar(&archstrs, "arch", nil, "architectures to build for (e.g., x86_64,ppc64le,arm64) -- default is all, unless specified in config.")
	cmd.Flags().StringSliceVarP(&extraKeys, "keyring-append", "k", []string{}, "path to extra keys to include in the keyring")
	cmd.Flags().StringSliceVar(&sbomFormats, "sbom-formats", sbom.DefaultOptions.Formats, "SBOM formats to output")
	cmd.Flags().StringSliceVarP(&extraRepos, "repository-append", "r", []string{}, "path to extra repositories to include")
	cmd.Flags().StringSliceVarP(&extraPackages, "package-append", "p", []string{}, "extra packages to include")
	cmd.Flags().StringSliceVar(&rawAnnotations, "annotations", []string{}, "OCI annotations to add. Separate with colon (key:value)")
	cmd.Flags().StringVar(&cacheDir, "cache-dir", "", "directory to use for caching apk packages and indexes (default '' means to use system-defined cache directory)")
	cmd.Flags().BoolVar(&offline, "offline", false, "do not use network to fetch packages (cache must be pre-populated)")

	// these are extra here just for publish; everything before is the same for BuildCmd as PublishCmd
	cmd.Flags().BoolVar(&local, "local", false, "publish image just to local Docker daemon")
	cmd.Flags().StringVar(&imageRefs, "image-refs", "", "path to file where a list of the published image references will be written")

	return cmd
}

func PublishCmd(ctx context.Context, outputRefs string, archs []types.Architecture, ropt []remote.Option, sbomPath string, buildOpts []build.Option, publishOpts []PublishOption) error {
	log := clog.FromContext(ctx)
	ctx, span := otel.Tracer("apko").Start(ctx, "PublishCmd")
	defer span.End()

	var opts publishOpt
	for _, opt := range publishOpts {
		if err := opt(&opts); err != nil {
			return err
		}
	}

	wd, err := os.MkdirTemp("", "apko-*")
	if err != nil {
		return fmt.Errorf("failed to create working directory: %w", err)
	}
	defer os.RemoveAll(wd)

	// build all of the components in the working directory
	idx, sboms, err := buildImageComponents(ctx, wd, archs, buildOpts...)
	if err != nil {
		return fmt.Errorf("failed to build image components: %w", err)
	}

	var (
		local           = opts.local
		tags            = opts.tags
		additionalTags  []string
		wantSBOM        = len(sboms) > 0 // it only generates sboms if wantSbom was true
		builtReferences = make([]string, 0)
	)

	if local {
		// TODO: We shouldn't even need to build the index if we're loading a single image.
		ref, err := oci.LoadIndex(ctx, idx, tags)
		if err != nil {
			return fmt.Errorf("loading index: %w", err)
		}
		log.Infof("using local option, exiting early")
		fmt.Println(ref.String())
		return nil
	}

	// publish each arch-specific image
	// TODO: This should just happen as part of PublishIndex.
	ref, err := name.ParseReference(tags[0])
	if err != nil {
		return fmt.Errorf("parsing %q as tag: %w", tags[0], err)
	}
	refs, err := oci.PublishImagesFromIndex(ctx, idx, ref.Context(), ropt...)
	if err != nil {
		return fmt.Errorf("publishing images from index: %w", err)
	}
	for _, ref := range refs {
		builtReferences = append(builtReferences, ref.String())
	}

	// publish the index
	finalDigest, err := oci.PublishIndex(ctx, idx, tags, ropt...)
	if err != nil {
		return fmt.Errorf("publishing image index: %w", err)
	}
	builtReferences = append(builtReferences, finalDigest.String())

	// output any file info requested
	// If provided, this is the name of the file to write digest referenced into
	if outputRefs != "" {
		//nolint:gosec // Make image ref file readable by non-root
		if err := os.WriteFile(outputRefs, []byte(strings.Join(builtReferences, "\n")+"\n"), 0o666); err != nil {
			return fmt.Errorf("failed to write digest: %w", err)
		}
	}

	// TODO: Why does this happen separately from PublishIndex?
	skipLocalCopy := strings.HasPrefix(finalDigest.Name(), fmt.Sprintf("%s/", oci.LocalDomain))
	g, ctx := errgroup.WithContext(ctx)
	for _, at := range additionalTags {
		at := at
		if skipLocalCopy {
			// TODO: We probably don't need this now that we return early.
			log.Warnf("skipping local domain tag %s", at)
			continue
		}
		g.Go(func() error {
			return oci.Copy(ctx, finalDigest.Name(), at, ropt...)
		})
	}
	if err := g.Wait(); err != nil {
		return err
	}

	// publish each arch-specific sbom
	// publish the index sbom
	if wantSBOM {
		// TODO: Why aren't these just attached to idx?

		// all sboms will be in the same directory
		if err := oci.PostAttachSBOMsFromIndex(
			ctx, idx, sboms, tags, ropt...,
		); err != nil {
			return fmt.Errorf("attaching sboms to index: %w", err)
		}
	}

	// copy sboms over to the sbomPath target directory
	if sbomPath != "" {
		for _, sbom := range sboms {
			// because os.Rename fails across partitions, we do our own
			if err := rename(sbom.Path, filepath.Join(sbomPath, filepath.Base(sbom.Path))); err != nil {
				return fmt.Errorf("moving sbom: %w", err)
			}
		}
	}

	// Write the image digest to STDOUT in order to enable command
	// composition e.g. kn service create --image=$(apko publish ...)
	fmt.Println(finalDigest)

	return nil
}

func parseAnnotations(rawAnnotations []string) (map[string]string, error) {
	annotations := map[string]string{}
	keyRegex := regexp.MustCompile(`^[a-z0-9-\.]+$`)
	for _, s := range rawAnnotations {
		parts := strings.SplitN(s, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("unable to parse annotation: %s", s)
		}
		if _, ok := annotations[parts[0]]; ok {
			return nil, fmt.Errorf("annotation %s defined more than once", parts[0])
		}
		if !keyRegex.MatchString(parts[0]) {
			return nil, fmt.Errorf("annotation key malformed: %s", parts[0])
		}
		if parts[1] == "" {
			return nil, fmt.Errorf("annotation %s value is empty", parts[0])
		}
		annotations[parts[0]] = parts[1]
	}
	return annotations, nil
}
