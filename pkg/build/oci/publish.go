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

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"go.opentelemetry.io/otel"
	"golang.org/x/sync/errgroup"

	"github.com/chainguard-dev/clog"
)

func LoadImage(ctx context.Context, image v1.Image, tags []string) (name.Reference, error) {
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
		if !strings.HasPrefix(localDstTag.Name(), fmt.Sprintf("%s/", LocalDomain)) {
			log.Infof("tagging local image %s as %s", localSrcTag.Name(), localDstTag.Name())
			if err := daemon.Tag(localSrcTag, localDstTag, daemon.WithContext(ctx)); err != nil {
				return name.Digest{}, err
			}
		}
	}
	return localSrcTag, nil
}

// PublishIndex given an v1.ImageIndex, publish it to a registry.
// `local` causes it to publish to the local docker daemon instead of the registry.
// Note that docker, when provided with a multi-architecture index, will load just the image inside for the provided
// platform, defaulting to the one on which the docker daemon is running.
// PublishIndex will determine that platform and use it to publish the updated index.
func PublishIndex(ctx context.Context, idx v1.ImageIndex, tags []string, remoteOpts ...remote.Option) (name.Digest, error) {
	log := clog.FromContext(ctx)

	// TODO(jason): Also set annotations on the index.

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

	var g errgroup.Group
	for _, tag := range toPublish {
		log.Infof("publishing index tag %v", tag)

		ref, err := name.ParseReference(tag)
		if err != nil {
			return name.Digest{}, fmt.Errorf("unable to parse reference: %w", err)
		}

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
func LoadIndex(ctx context.Context, idx v1.ImageIndex, tags []string) (name.Reference, error) {
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
	img, err := idx.Image(useManifest.Digest)
	if err != nil {
		return name.Digest{}, fmt.Errorf("reading child image %q", useManifest.Digest.String())
	}

	log.Infof("using best guess single-arch image for local tags (%s/%s)", goos, goarch)
	return LoadImage(ctx, img, tags)
}

// PublishImagesFromIndex publishes all images from an index to a remote registry.
// The only difference between this and PublishIndex is that PublishIndex pushes out all blobs and referenced manifests
// from within the index. This adds pushing the referenced Image artifacts along with appropriate tags.
func PublishImagesFromIndex(ctx context.Context, idx v1.ImageIndex, repo name.Repository, remoteOpts ...remote.Option) ([]name.Digest, error) {
	_, span := otel.Tracer("apko").Start(ctx, "PublishImagesFromIndex")
	defer span.End()

	manifest, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("failed to get index manifest: %w", err)
	}

	digests := make([]name.Digest, len(manifest.Manifests))

	var g errgroup.Group
	for i, m := range manifest.Manifests {
		i, m := i, m

		dig := repo.Digest(m.Digest.String())
		digests[i] = dig

		g.Go(func() error {
			img, err := idx.Image(m.Digest)
			if err != nil {
				return fmt.Errorf("failed to get image for %v from index: %w", m, err)
			}

			return remote.Write(dig, img, remoteOpts...)
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return digests, nil
}
