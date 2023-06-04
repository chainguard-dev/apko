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
	"sync"
	"time"

	"github.com/avast/retry-go"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v2/pkg/oci"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/cosign/v2/pkg/oci/walk"
	"golang.org/x/sync/errgroup"

	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/log"
)

// PublishImage publishes an image to a registry.
// `local` determines if it should push to the local docker daemon or to the actual registry.
// `shouldPushTags` determines whether to push the tags provided in the `tags` parameter, or whether
// to treat the first tag as a digest and push that instead.
func PublishImage(ctx context.Context, image oci.SignedImage, local, shouldPushTags bool, logger log.Logger, tags []string, remoteOpts ...remote.Option) (name.Digest, error) {
	h, err := image.Digest()
	if err != nil {
		return name.Digest{}, fmt.Errorf("failed to compute digest: %w", err)
	}

	digest := name.Digest{}
	toPublish := tags
	msg := "publish image tag"
	if !shouldPushTags {
		toPublish = []string{fmt.Sprintf("%s@%s", strings.Split(tags[0], ":")[0], h.String())}
		msg = "publishing image without tag (digest only)"
	}
	for _, tag := range toPublish {
		logger.Printf("%s %v", msg, tag)
		digest, err = publishTagFromImage(ctx, image, tag, h, local, logger, remoteOpts...)
		if err != nil {
			return name.Digest{}, err
		}
	}

	return digest, nil
}

// PublishImageFromLayer convenience function that creates an image from a v1.Layer, and then publishes that.
// Just wraps BuildImageFromLayer and PublishImage.
// Options provided are applied either to BuildImageFromlayer or PublishImage.
func PublishImageFromLayer(ctx context.Context, layer v1.Layer, ic types.ImageConfiguration, created time.Time, arch types.Architecture, logger log.Logger, local, shouldPushTags bool, tags []string, remoteOpts ...remote.Option) (name.Digest, oci.SignedImage, error) {
	v1Image, err := BuildImageFromLayer(layer, ic, created, arch, logger)
	if err != nil {
		return name.Digest{}, nil, err
	}
	dig, err := PublishImage(ctx, v1Image, local, shouldPushTags, logger, tags, remoteOpts...)
	return dig, v1Image, err
}

// PublishIndex given an oci.SignedImageIndex, publish it to a registry.
// `local` causes it to publish to the local docker daemon instead of the registry.
// Note that docker, when provided with a multi-architecture index, will load just the image inside for the provided
// platform, defaulting to the one on which the docker daemon is running.
// PublishIndex will determine that platform and use it to publish the updated index.
func PublishIndex(ctx context.Context, idx oci.SignedImageIndex, logger log.Logger, local bool, shouldPushTags bool, tags []string, remoteOpts ...remote.Option) (name.Digest, oci.SignedImageIndex, error) {
	// If attempting to save locally, pick the native architecture
	// and use that cached image for local tags
	// Ported from https://github.com/ko-build/ko/blob/main/pkg/publish/daemon.go#L92-L168
	if local {
		im, err := idx.IndexManifest()
		if err != nil {
			return name.Digest{}, nil, err
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
		localSrcTagStr := fmt.Sprintf("%s/%s:%s", LocalDomain, LocalRepo, useManifest.Digest.Hex)
		logger.Printf("using best guess single-arch image for local tags: %s (%s/%s)", localSrcTagStr, goos, goarch)
		localSrcTag, err := name.NewTag(localSrcTagStr)
		if err != nil {
			return name.Digest{}, nil, err
		}
		for _, tag := range tags {
			localDstTag, err := name.NewTag(tag)
			if err != nil {
				return name.Digest{}, nil, err
			}
			if strings.HasPrefix(localSrcTag.Name(), fmt.Sprintf("%s/", LocalDomain)) {
				logger.Warnf("skipping local domain tagging %s as %s", localSrcTag.Name(), localDstTag.Name())
			} else {
				logger.Printf("tagging local image %s as %s", localSrcTag.Name(), localDstTag.Name())
				if err := daemon.Tag(localSrcTag, localDstTag); err != nil {
					return name.Digest{}, nil, err
				}
			}
		}
		digest, err := name.NewDigest(fmt.Sprintf("%s@%s", localSrcTag.Name(), useManifest.Digest.String()))
		if err != nil {
			return name.Digest{}, nil, err
		}
		return digest, idx, nil
	}

	h, err := idx.Digest()
	if err != nil {
		return name.Digest{}, nil, err
	}

	digest := name.Digest{}
	msg := "publishing index tag"
	toPublish := tags
	if !shouldPushTags {
		toPublish = []string{fmt.Sprintf("%s@%s", strings.Split(tags[0], ":")[0], h.String())}
		msg = "publishing index without tag (digest only)"
	}
	for _, tag := range toPublish {
		logger.Printf("%s %v", msg, tag)
		digest, err = publishTagFromIndex(ctx, idx, tag, h, logger, remoteOpts...)
		if err != nil {
			return name.Digest{}, nil, err
		}
	}

	return digest, idx, nil
}

// publishTagFromIndex publishes a single tag from an oci.SignedImageIndex,
// as well as any attached signatures/SBoMs.
func publishTagFromIndex(ctx context.Context, index oci.SignedImageIndex, imageRef string, hash v1.Hash, logger log.Logger, remoteOpts ...remote.Option) (name.Digest, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return name.Digest{}, fmt.Errorf("unable to parse reference: %w", err)
	}

	var g errgroup.Group

	// Write any attached SBOMs/signatures (recursively)
	wp := writePeripherals(ref, logger, remoteOpts...)
	if err := walk.SignedEntity(ctx, index, func(ctx context.Context, se oci.SignedEntity) error {
		g.Go(func() error {
			return wp(ctx, se)
		})
		return nil
	}); err != nil {
		return name.Digest{}, err
	}

	g.Go(func() error {
		return retry.Do(func() error {
			return remote.WriteIndex(ref, index, remoteOpts...)
		})
	})
	if err := g.Wait(); err != nil {
		return name.Digest{}, fmt.Errorf("failed to publish: %w", err)
	}

	return ref.Context().Digest(hash.String()), nil
}

// publishTagFromImage publishes a single tag from an oci.SignedImage,
// as well as any attached signatures/SBoMs.
// Supports pushing to local docker daemon via the `local` flag.
func publishTagFromImage(ctx context.Context, image oci.SignedImage, imageRef string, hash v1.Hash, local bool, logger log.Logger, remoteOpts ...remote.Option) (name.Digest, error) {
	imgRef, err := name.ParseReference(imageRef)
	if err != nil {
		return name.Digest{}, fmt.Errorf("unable to parse reference: %w", err)
	}

	if local {
		localSrcTagStr := fmt.Sprintf("%s/%s:%s", LocalDomain, LocalRepo, hash.Hex)
		localSrcTag, err := name.NewTag(localSrcTagStr)
		if err != nil {
			return name.Digest{}, err
		}
		logger.Infof("saving OCI image locally: %s", localSrcTag.Name())
		resp, err := daemon.Write(localSrcTag, image)
		if err != nil {
			logger.Errorf("docker daemon error: %s", strings.ReplaceAll(resp, "\n", "\\n"))
			return name.Digest{}, fmt.Errorf("failed to save OCI image locally: %w", err)
		}
		logger.Debugf("docker daemon response: %s", strings.ReplaceAll(resp, "\n", "\\n"))
		localDstTag, err := name.NewTag(imageRef)
		if err != nil {
			return name.Digest{}, err
		}
		if strings.HasPrefix(localSrcTag.Name(), fmt.Sprintf("%s/", LocalDomain)) {
			logger.Warnf("skipping local domain tagging %s as %s", localSrcTag.Name(), localDstTag.Name())
		} else {
			logger.Printf("tagging local image %s as %s", localSrcTag.Name(), localDstTag.Name())
			if err := daemon.Tag(localSrcTag, localDstTag); err != nil {
				return name.Digest{}, err
			}
		}
		return name.NewDigest(fmt.Sprintf("%s@%s", localSrcTag.Name(), hash))
	}

	var g errgroup.Group

	// Write any attached SBOMs/signatures.
	wp := writePeripherals(imgRef, logger, remoteOpts...)
	g.Go(func() error {
		return wp(ctx, image)
	})

	g.Go(func() error {
		return retry.Do(func() error {
			return remote.Write(imgRef, image, remoteOpts...)
		})
	})

	if err := g.Wait(); err != nil {
		return name.Digest{}, fmt.Errorf("failed to publish: %w", err)
	}
	return imgRef.Context().Digest(hash.String()), nil
}

// PublishImagesFromIndex publishes all images from an index to a remote registry.
// The only difference between this and PublishIndex is that PublishIndex pushes out all blobs and referenced manifests
// from within the index. This adds pushing the referenced SignedImage artifacts along with appropriate tags.
func PublishImagesFromIndex(ctx context.Context, idx oci.SignedImageIndex, local, shouldPushTags bool, logger log.Logger, tags []string, remoteOpts ...remote.Option) (digests []name.Digest, err error) {
	manifest, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("failed to get index manifest: %w", err)
	}
	var (
		g   errgroup.Group
		mtx sync.Mutex
	)
	for _, m := range manifest.Manifests {
		m := m
		g.Go(func() error {
			img, err := idx.SignedImage(m.Digest)
			if err != nil {
				return fmt.Errorf("failed to get image for %v from index: %w", m, err)
			}
			if dig, err := PublishImage(ctx, img, local, shouldPushTags, logger, tags, remoteOpts...); err != nil {
				return err
			} else {
				mtx.Lock()
				digests = append(digests, dig)
				mtx.Unlock()
			}
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
func writePeripherals(tag name.Reference, logger log.Logger, opt ...remote.Option) walk.Fn {
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

		if err := retry.Do(func() error {
			return remote.Write(ref, f, opt...)
		}); err != nil {
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
		logger.Printf("Published SBOM %v", ref)

		return nil
	}
}

// Copt copies an image from one registry repository to another.
func Copy(ctx context.Context, src, dst string, remoteOpts ...remote.Option) error {
	log.DefaultLogger().Infof("Copying %s to %s", src, dst)
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
