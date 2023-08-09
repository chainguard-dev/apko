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
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/awslabs/amazon-ecr-credential-helper/ecr-login"
	"github.com/chrismellard/docker-credential-acr-env/pkg/credhelper"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/authn/github"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/google"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel"
	"golang.org/x/sync/errgroup"

	"chainguard.dev/apko/pkg/apk"
	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/build/oci"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/iocomb"
	"chainguard.dev/apko/pkg/log"
	"chainguard.dev/apko/pkg/sbom"
)

func publish() *cobra.Command {
	var imageRefs string
	var useDockerMediaTypes bool
	var buildDate string
	var sbomPath string
	var packageVersionTag string
	var packageVersionTagStem bool
	var packageVersionTagPrefix string
	var tagSuffix string
	var sbomFormats []string
	var archstrs []string
	var extraKeys []string
	var extraRepos []string
	var extraPackages []string
	var buildOptions []string
	var rawAnnotations []string
	var logPolicy []string
	var debugEnabled bool
	var quietEnabled bool
	var withVCS bool
	var writeSBOM bool
	var local bool
	var stageTags string
	var cacheDir string

	cmd := &cobra.Command{
		Use:   "publish",
		Short: "Build and publish an image",
		Long: `Publish a built image from a YAML configuration file.

It is assumed that you have used "docker login" to store credentials
in a keychain.`,
		Example: `  apko publish <config.yaml> <tag...>`,
		Args:    cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(logPolicy) == 0 {
				if quietEnabled {
					logPolicy = []string{"builtin:discard"}
				} else {
					logPolicy = []string{"builtin:stderr"}
				}
			}

			logWriter, err := iocomb.Combine(logPolicy)
			if err != nil {
				return fmt.Errorf("invalid logging policy: %w", err)
			}
			logger := log.NewLogger(logWriter)

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
				google.Keychain,
				authn.NewKeychainFromHelper(ecr.NewECRHelper(ecr.WithLogger(io.Discard))),
				authn.NewKeychainFromHelper(credhelper.NewACRCredentialsHelper()),
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

			if err := PublishCmd(cmd.Context(), imageRefs, archs, remoteOpts,
				[]build.Option{
					build.WithLogger(logger),
					build.WithConfig(args[0]),
					build.WithDockerMediatypes(useDockerMediaTypes),
					build.WithBuildDate(buildDate),
					build.WithAssertions(build.RequireGroupFile(true), build.RequirePasswdFile(true)),
					build.WithSBOM(sbomPath),
					build.WithSBOMFormats(sbomFormats),
					build.WithExtraKeys(extraKeys),
					build.WithExtraRepos(extraRepos),
					build.WithExtraPackages(extraPackages),
					build.WithTags(args[1:]...),
					build.WithDebugLogging(debugEnabled),
					build.WithVCS(withVCS),
					build.WithAnnotations(annotations),
					build.WithBuildOptions(buildOptions),
					build.WithCacheDir(cacheDir),
				},
				[]PublishOption{
					// these are extra here just for publish; everything before is the same for BuildCmd as PublishCmd
					WithLogger(logger),
					WithPackageVersionTag(packageVersionTag),
					WithPackageVersionTagStem(packageVersionTagStem),
					WithPackageVersionTagPrefix(packageVersionTagPrefix),
					WithTagSuffix(tagSuffix),
					WithLocal(local),
					WithStageTags(stageTags),
					WithTags(args[1:]...),
				},
			); err != nil {
				return err
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&useDockerMediaTypes, "use-docker-mediatypes", false, "use Docker mediatypes for image layers/manifest")
	cmd.Flags().BoolVar(&debugEnabled, "debug", false, "enable debug logging")
	cmd.Flags().BoolVar(&quietEnabled, "quiet", false, "disable logging")
	cmd.Flags().BoolVar(&withVCS, "vcs", true, "detect and embed VCS URLs")
	cmd.Flags().StringVar(&buildDate, "build-date", "", "date used for the timestamps of the files inside the image")
	cmd.Flags().BoolVar(&writeSBOM, "sbom", true, "generate an SBOM")
	cmd.Flags().StringVar(&sbomPath, "sbom-path", "", "path to write the SBOMs")
	cmd.Flags().StringSliceVar(&archstrs, "arch", nil, "architectures to build for (e.g., x86_64,ppc64le,arm64) -- default is all, unless specified in config.")
	cmd.Flags().StringSliceVarP(&extraKeys, "keyring-append", "k", []string{}, "path to extra keys to include in the keyring")
	cmd.Flags().StringSliceVar(&sbomFormats, "sbom-formats", sbom.DefaultOptions.Formats, "SBOM formats to output")
	cmd.Flags().StringSliceVarP(&extraRepos, "repository-append", "r", []string{}, "path to extra repositories to include")
	cmd.Flags().StringSliceVar(&buildOptions, "build-option", []string{}, "build options to enable")
	cmd.Flags().StringSliceVarP(&extraPackages, "package-append", "p", []string{}, "extra packages to include")
	_ = cmd.Flags().MarkDeprecated("build-option", "use --package-append instead")
	cmd.Flags().StringSliceVar(&logPolicy, "log-policy", []string{}, "logging policy to use")
	cmd.Flags().StringSliceVar(&rawAnnotations, "annotations", []string{}, "OCI annotations to add. Separate with colon (key:value)")
	cmd.Flags().StringVar(&cacheDir, "cache-dir", "", "directory to use for caching apk packages and indexes (default '' means to use system-defined cache directory)")

	// these are extra here just for publish; everything before is the same for BuildCmd as PublishCmd
	cmd.Flags().StringVar(&packageVersionTag, "package-version-tag", "", "Tag the final image with the version of the package passed in")
	cmd.Flags().BoolVar(&packageVersionTagStem, "package-version-tag-stem", false, "add additional tags by stemming the package version")
	cmd.Flags().StringVar(&packageVersionTagPrefix, "package-version-tag-prefix", "", "prefix for package version tag(s)")
	cmd.Flags().StringVar(&tagSuffix, "tag-suffix", "", "suffix to use for automatically generated tags")
	cmd.Flags().BoolVar(&local, "local", false, "publish image just to local Docker daemon")
	cmd.Flags().StringVar(&stageTags, "stage-tags", "", "path to file to write list of tags to instead of publishing them")
	cmd.Flags().StringVar(&imageRefs, "image-refs", "", "path to file where a list of the published image references will be written")

	return cmd
}

func PublishCmd(ctx context.Context, outputRefs string, archs []types.Architecture, ropt []remote.Option, buildOpts []build.Option, publishOpts []PublishOption) error {
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
	idx, sboms, pkgs, err := buildImageComponents(ctx, wd, archs, buildOpts...)
	if err != nil {
		return fmt.Errorf("failed to build image components: %w", err)
	}

	var (
		stageTags       = opts.stageTags
		shouldPushTags  = stageTags == ""
		local           = opts.local
		logger          = opts.logger
		tags            = opts.tags
		additionalTags  []string
		wantSBOM        = len(sboms) > 0 // it only generates sboms if wantSbom was true
		builtReferences = make([]string, 0)
	)
	// safety
	if logger == nil {
		logger = log.NewLogger(os.Stderr)
	}

	if local {
		// TODO: We shouldn't even need to build the index if we're loading a single image.
		ref, err := oci.LoadIndex(ctx, idx, logger, tags)
		if err != nil {
			return fmt.Errorf("loading index: %w", err)
		}
		logger.Printf("using local option, exiting early")
		fmt.Println(ref.String())
		return nil
	}

	// generate additional tags from the package information per architecture
	tagsByArch := make(map[types.Architecture][]string)
	for arch, pkgList := range pkgs {
		addTags, err := apk.AdditionalTags(pkgList, opts.logger, tags, opts.packageVersionTag, opts.packageVersionTagPrefix, opts.tagSuffix, opts.packageVersionTagStem)
		if err != nil {
			return fmt.Errorf("failed to generate additional tags for arch %s: %w", arch, err)
		}
		tagsByArch[arch] = append(tags, addTags...)
	}

	// if the tags are not identical across arches, that is an error
	allTagsMap := make(map[string]bool)
	for arch, archTags := range tagsByArch {
		tagSet := make(map[string]bool)
		for _, tag := range archTags {
			tagSet[tag] = true
		}
		if len(allTagsMap) == 0 {
			allTagsMap = tagSet
			continue
		}
		if len(tagSet) != len(allTagsMap) {
			return fmt.Errorf("tags for arch %s are not identical to other arches", arch)
		}
		for tag := range tagSet {
			if !allTagsMap[tag] {
				return fmt.Errorf("tags for arch %s are not identical to other arches", arch)
			}
		}
	}
	// and now generate a slice
	allTags := make([]string, 0, len(allTagsMap))
	for tag := range allTagsMap {
		allTags = append(allTags, tag)
	}

	// publish each arch-specific image
	// TODO: This should just happen as part of PublishIndex.
	ref, err := name.ParseReference(tags[0])
	if err != nil {
		return fmt.Errorf("parsing %q as tag: %w", tags[0], err)
	}
	refs, err := oci.PublishImagesFromIndex(ctx, idx, logger, ref.Context(), ropt...)
	if err != nil {
		return fmt.Errorf("publishing images from index: %w", err)
	}
	for _, ref := range refs {
		builtReferences = append(builtReferences, ref.String())
	}

	// publish the index
	finalDigest, err := oci.PublishIndex(ctx, idx, logger, shouldPushTags, allTags, ropt...)
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

	if !shouldPushTags {
		allTags := tags
		allTags = append(allTags, additionalTags...)
		tmp := map[string]bool{}
		for _, tag := range allTags {
			if !strings.Contains(tag, ":") {
				tag = fmt.Sprintf("%s:latest", tag)
			}
			tmp[tag] = true
		}
		sortedUniqueTags := make([]string, 0, len(tmp))
		for k := range tmp {
			sortedUniqueTags = append(sortedUniqueTags, k)
		}
		sort.Strings(sortedUniqueTags)
		logger.Printf("Writing list of tags to %s (%d total)", stageTags, len(sortedUniqueTags))

		//nolint:gosec // Make tags file readable by non-root
		if err := os.WriteFile(stageTags, []byte(strings.Join(sortedUniqueTags, "\n")+"\n"), 0o666); err != nil {
			return fmt.Errorf("failed to write tags: %w", err)
		}
	} else {
		// TODO: Why does this happen separately from PublishIndex?
		skipLocalCopy := strings.HasPrefix(finalDigest.Name(), fmt.Sprintf("%s/", oci.LocalDomain))
		g, ctx := errgroup.WithContext(ctx)
		for _, at := range additionalTags {
			at := at
			if skipLocalCopy {
				// TODO: We probably don't need this now that we return early.
				logger.Warnf("skipping local domain tag %s", at)
				continue
			}
			g.Go(func() error {
				return oci.Copy(ctx, finalDigest.Name(), at, ropt...)
			})
		}
		if err := g.Wait(); err != nil {
			return err
		}
	}

	// publish each arch-specific sbom
	// publish the index sbom
	if wantSBOM {
		// TODO: Why aren't these just attached to idx?

		// all sboms will be in the same directory
		if err := oci.PostAttachSBOMsFromIndex(
			ctx, idx, sboms, logger, tags, ropt...,
		); err != nil {
			return fmt.Errorf("attaching sboms to index: %w", err)
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
