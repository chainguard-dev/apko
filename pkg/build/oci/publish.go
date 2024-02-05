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

package oci

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/chainguard-dev/clog"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v2/pkg/oci"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/cosign/v2/pkg/oci/walk"
	"go.opentelemetry.io/otel"
	"golang.org/x/sync/errgroup"
)

// PublishImage publishes an image to a registry.
// `local` determines if it should push to the local docker daemon or to the actual registry.
// `shouldPushTags` determines whether to push the tags provided in the `tags` parameter, or whether
// to treat the first tag as a digest and push that instead.
func PublishImage(ctx context.Context, image oci.SignedImage, shouldPushTags bool, tags []string, remoteOpts ...remote.Option) (name.Digest, error) {
	log := clog.FromContext(ctx)
	ref, err := name.ParseReference(tags[0])
	if err != nil {
		return name.Digest{}, fmt.Errorf("parsing tag %q: %w", tags[0], err)
	}

	hash, err := image.Digest()
	if err != nil {
		return name.Digest{}, fmt.Errorf("failed to compute digest: %w", err)
	}

	dig := ref.Context().Digest(hash.String())

	toPublish := tags
	msg := "publish image tag"

	if !shouldPushTags {
		toPublish = []string{dig.String()}
		msg = "publishing image without tag (digest only)"
	}

	g, ctx := errgroup.WithContext(ctx)
	for _, tag := range toPublish {
		tag := tag
		g.Go(func() error {
			log.Infof("%s %v", msg, tag)
			ref, err := name.ParseReference(tag)
			if err != nil {
				return fmt.Errorf("unable to parse reference: %w", err)
			}

			// Write any attached SBOMs/signatures.
			wp := writePeripherals(ctx, ref, remoteOpts...)
			g.Go(func() error {
				return wp(ctx, image)
			})

			g.Go(func() error {
				return remote.Write(ref, image, remoteOpts...)
			})

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return name.Digest{}, fmt.Errorf("failed to publish: %w", err)
	}

	return dig, nil
}

func LoadImage(ctx context.Context, image oci.SignedImage, tags []string) (name.Reference, error) {
	log := clog.FromContext(ctx)
	hash, err := image.Digest()
	if err != nil {
		return name.Digest{}, err
	}
	localSrcTagStr := fmt.Sprintf("%s/%s:%s", LocalDomain, LocalRepo, hash.Hex)
	localSrcTag, err := name.NewTag(localSrcTagStr)
	if err != nil {
		return name.Digest{}, err
	}
	log.Infof("saving OCI image locally: %s", localSrcTag.Name())
	resp, err := daemon.Write(localSrcTag, image, daemon.WithContext(ctx))
	if err != nil {
		log.Errorf("docker daemon error: %s", strings.ReplaceAll(resp, "\n", "\\n"))
		return name.Digest{}, fmt.Errorf("failed to save OCI image locally: %w", err)
	}
	log.Debugf("docker daemon response: %s", strings.ReplaceAll(resp, "\n", "\\n"))
	for _, tag := range tags {
		localDstTag, err := name.NewTag(tag)
		if err != nil {
			return name.Digest{}, err
		}
		if strings.HasPrefix(localSrcTag.Name(), fmt.Sprintf("%s/", LocalDomain)) {
			log.Warnf("skipping local domain tagging %s as %s", localSrcTag.Name(), localDstTag.Name())
		} else {
			log.Infof("tagging local image %s as %s", localSrcTag.Name(), localDstTag.Name())
			if err := daemon.Tag(localSrcTag, localDstTag, daemon.WithContext(ctx)); err != nil {
				return name.Digest{}, err
			}
		}
	}
	return localSrcTag, nil
}

// PublishIndex given an oci.SignedImageIndex, publish it to a registry.
// `local` causes it to publish to the local docker daemon instead of the registry.
// Note that docker, when provided with a multi-architecture index, will load just the image inside for the provided
// platform, defaulting to the one on which the docker daemon is running.
// PublishIndex will determine that platform and use it to publish the updated index.
func PublishIndex(ctx context.Context, idx oci.SignedImageIndex, tags []string, remoteOpts ...remote.Option) (name.Digest, error) {
	log := clog.FromContext(ctx)

	// TODO(jason): Also set annotations on the index. ggcr's
	// pkg/v1/mutate.Annotations will drop the interface methods from
	// oci.SignedImageIndex, so we may need to reimplement
	// mutate.Annotations in ocimutate to keep it for now.

	ref, err := name.ParseReference(tags[0])
	if err != nil {
		return name.Digest{}, fmt.Errorf("parsing tag %q: %w", tags[0], err)
	}

	h, err := idx.Digest()
	if err != nil {
		return name.Digest{}, err
	}

	dig := ref.Context().Digest(h.String())

	toPublish := tags

	g, ctx := errgroup.WithContext(ctx)
	for _, tag := range toPublish {
		log.Infof("publishing index tag %v", tag)

		ref, err := name.ParseReference(tag)
		if err != nil {
			return name.Digest{}, fmt.Errorf("unable to parse reference: %w", err)
		}

		// Write any attached SBOMs/signatures (recursively)
		g.Go(func() error {
			wp := writePeripherals(ctx, ref, remoteOpts...)
			return walk.SignedEntity(ctx, idx, func(ctx context.Context, se oci.SignedEntity) error {
				g.Go(func() error {
					return wp(ctx, se)
				})
				return nil
			})
		})

		g.Go(func() error {
			return remote.WriteIndex(ref, idx, remoteOpts...)
		})
	}
	if err := g.Wait(); err != nil {
		return name.Digest{}, fmt.Errorf("failed to publish: %w", err)
	}

	return dig, nil
}

// If attempting to save locally, pick the native architecture
// and use that cached image for local tags
// Ported from https://github.com/ko-build/ko/blob/main/pkg/publish/daemon.go#L92-L168
func LoadIndex(ctx context.Context, idx oci.SignedImageIndex, tags []string) (name.Reference, error) {
	log := clog.FromContext(ctx)
	im, err := idx.IndexManifest()
	if err != nil {
		return name.Digest{}, err
	}
	goos, goarch := os.Getenv("GOOS"), os.Getenv("GOARCH")
	if goos == "" {
		goos = "linux"
	}
	if goarch == "" {
		goarch = "amd64"
	}
	// Default to just using the first one in the list if we cannot match
	useManifest := im.Manifests[0]
	for _, manifest := range im.Manifests {
		if manifest.Platform == nil {
			continue
		}
		if manifest.Platform.OS != goos {
			continue
		}
		if manifest.Platform.Architecture != goarch {
			continue
		}
		useManifest = manifest
	}
	img, err := idx.SignedImage(useManifest.Digest)
	if err != nil {
		return name.Digest{}, fmt.Errorf("reading child image %q", useManifest.Digest.String())
	}

	log.Infof("using best guess single-arch image for local tags (%s/%s)", goos, goarch)
	return LoadImage(ctx, img, tags)
}

// PublishImagesFromIndex publishes all images from an index to a remote registry.
// The only difference between this and PublishIndex is that PublishIndex pushes out all blobs and referenced manifests
// from within the index. This adds pushing the referenced SignedImage artifacts along with appropriate tags.
func PublishImagesFromIndex(ctx context.Context, idx oci.SignedImageIndex, repo name.Repository, remoteOpts ...remote.Option) ([]name.Digest, error) {
	ctx, span := otel.Tracer("apko").Start(ctx, "PublishImagesFromIndex")
	defer span.End()

	manifest, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("failed to get index manifest: %w", err)
	}

	digests := make([]name.Digest, len(manifest.Manifests))

	g, ctx := errgroup.WithContext(ctx)
	for i, m := range manifest.Manifests {
		i, m := i, m

		dig := repo.Digest(m.Digest.String())
		digests[i] = dig

		g.Go(func() error {
			img, err := idx.SignedImage(m.Digest)
			if err != nil {
				return fmt.Errorf("failed to get image for %v from index: %w", m, err)
			}

			g.Go(func() error {
				// Write any attached SBOMs/signatures.
				wp := writePeripherals(ctx, dig, remoteOpts...)
				return wp(ctx, img)
			})

			g.Go(func() error {
				return remote.Write(dig, img, remoteOpts...)
			})

			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return digests, nil
}

// writePeripherals returns a function to write any attached SBOMs/signatures.
// Its output is meant to be passed to walk.SignedEntity().
func writePeripherals(ctx context.Context, tag name.Reference, opt ...remote.Option) walk.Fn {
	log := clog.FromContext(ctx)
	ociOpts := []ociremote.Option{ociremote.WithRemoteOptions(opt...)}

	// Respect COSIGN_REPOSITORY
	targetRepoOverride, err := ociremote.GetEnvTargetRepository()
	if err != nil {
		return func(ctx context.Context, se oci.SignedEntity) error { return err }
	}
	if (targetRepoOverride != name.Repository{}) {
		ociOpts = append(ociOpts, ociremote.WithTargetRepository(targetRepoOverride))
	}

	return func(ctx context.Context, se oci.SignedEntity) error {
		h, err := se.(interface{ Digest() (v1.Hash, error) }).Digest()
		if err != nil {
			return err
		}

		// TODO(mattmoor): We should have a WriteSBOM helper upstream.
		digest := tag.Context().Digest(h.String()) // Don't *get* the tag, we know the digest
		ref, err := ociremote.SBOMTag(digest, ociOpts...)
		if err != nil {
			return err
		}

		f, err := se.Attachment("sbom")
		if err != nil {
			// Some levels (e.g. the index) may not have an SBOM,
			// just like some levels may not have signatures/attestations.
			return nil
		}

		if err := remote.Write(ref, f, opt...); err != nil {
			return fmt.Errorf("writing sbom: %w", err)
		}

		// TODO(mattmoor): Don't enable this until we start signing or it
		// will publish empty signatures!
		// if err := ociremote.WriteSignatures(tag.Context(), se, ociOpts...); err != nil {
		// 	return err
		// }

		// TODO(mattmoor): Are there any attestations we want to write?
		// if err := ociremote.WriteAttestations(tag.Context(), se, ociOpts...); err != nil {
		// 	return err
		// }
		log.Infof("Published SBOM %v", ref)

		return nil
	}
}

// Copt copies an image from one registry repository to another.
func Copy(ctx context.Context, src, dst string, remoteOpts ...remote.Option) error {
	log := clog.FromContext(ctx)
	ctx, span := otel.Tracer("apko").Start(ctx, "oci.Copy")
	defer span.End()

	log.Infof("Copying %s to %s", src, dst)
	srcRef, err := name.ParseReference(src)
	if err != nil {
		return err
	}
	dstRef, err := name.ParseReference(dst)
	if err != nil {
		return err
	}
	desc, err := remote.Get(srcRef, remoteOpts...)
	if err != nil {
		return fmt.Errorf("fetching %s: %w", src, err)
	}
	pusher, err := remote.NewPusher(remoteOpts...)
	if err != nil {
		return err
	}
	if err := pusher.Push(ctx, dstRef, desc); err != nil {
		return fmt.Errorf("tagging %s with tag %s: %w", src, dst, err)
	}

	return nil
}
