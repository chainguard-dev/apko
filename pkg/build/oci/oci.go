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
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/avast/retry-go"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	v1tar "github.com/google/go-containerregistry/pkg/v1/tarball"
	ggcrtypes "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/google/shlex"
	"github.com/sigstore/cosign/v2/pkg/oci"
	ocimutate "github.com/sigstore/cosign/v2/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/cosign/v2/pkg/oci/signed"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	"github.com/sigstore/cosign/v2/pkg/oci/walk"
	ctypes "github.com/sigstore/cosign/v2/pkg/types"
	"golang.org/x/sync/errgroup"

	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/log"
	"chainguard.dev/apko/pkg/options"
)

const (
	LocalDomain = "apko.local"
	LocalRepo   = "cache"
)

func BuildImageFromLayer(layer v1.Layer, ic types.ImageConfiguration, created time.Time, arch types.Architecture, logger log.Logger) (oci.SignedImage, error) {
	mediaType, err := layer.MediaType()
	if err != nil {
		return nil, fmt.Errorf("accessing layer MediaType: %w", err)
	}
	imageType := humanReadableImageType(mediaType)
	logger.Printf("building image from layer")

	digest, err := layer.Digest()
	if err != nil {
		return nil, fmt.Errorf("could not calculate layer digest: %w", err)
	}

	diffid, err := layer.DiffID()
	if err != nil {
		return nil, fmt.Errorf("could not calculate layer diff id: %w", err)
	}

	logger.Printf("%s layer digest: %v", imageType, digest)
	logger.Printf("%s layer diffID: %v", imageType, diffid)

	adds := make([]mutate.Addendum, 0, 1)
	adds = append(adds, mutate.Addendum{
		Layer: layer,
		History: v1.History{
			Author:    "apko",
			Comment:   "This is an apko single-layer image",
			CreatedBy: "apko",
			Created:   v1.Time{Time: created},
		},
	})

	emptyImage := empty.Image
	if mediaType == ggcrtypes.OCILayer {
		// If building an OCI layer, then we should assume OCI manifest and config too
		emptyImage = mutate.MediaType(emptyImage, ggcrtypes.OCIManifestSchema1)
		emptyImage = mutate.ConfigMediaType(emptyImage, ggcrtypes.OCIConfigJSON)
	}
	v1Image, err := mutate.Append(emptyImage, adds...)
	if err != nil {
		return nil, fmt.Errorf("unable to append %s layer to empty image: %w", imageType, err)
	}

	annotations := ic.Annotations
	if annotations == nil {
		annotations = map[string]string{}
	}
	if ic.VCSUrl != "" {
		if url, hash, ok := strings.Cut(ic.VCSUrl, "@"); ok {
			annotations["org.opencontainers.image.source"] = url
			annotations["org.opencontainers.image.revision"] = hash
		}
	}

	if mediaType != ggcrtypes.DockerLayer && len(annotations) > 0 {
		v1Image = mutate.Annotations(v1Image, annotations).(v1.Image)
	}

	cfg, err := v1Image.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("unable to get %s config file: %w", imageType, err)
	}

	cfg = cfg.DeepCopy()
	cfg.Author = "github.com/chainguard-dev/apko"
	platform := arch.ToOCIPlatform()
	cfg.Architecture = platform.Architecture
	cfg.Variant = platform.Variant
	cfg.Created = v1.Time{Time: created}
	cfg.Config.Labels = make(map[string]string)
	cfg.OS = "linux"

	// NOTE: Need to allow empty Entrypoints. The runtime will override to `/bin/sh -c` and handle quoting
	switch {
	case ic.Entrypoint.ShellFragment != "":
		cfg.Config.Entrypoint = []string{"/bin/sh", "-c", ic.Entrypoint.ShellFragment}
	case ic.Entrypoint.Command != "":
		splitcmd, err := shlex.Split(ic.Entrypoint.Command)
		if err != nil {
			return nil, fmt.Errorf("unable to parse entrypoint command: %w", err)
		}
		cfg.Config.Entrypoint = splitcmd
	}

	if ic.Cmd != "" {
		splitcmd, err := shlex.Split(ic.Cmd)
		if err != nil {
			return nil, fmt.Errorf("unable to parse cmd: %w", err)
		}
		cfg.Config.Cmd = splitcmd
	}

	if ic.WorkDir != "" {
		cfg.Config.WorkingDir = ic.WorkDir
	}

	// Set these environment variables if they are not already set.
	if ic.Environment == nil {
		ic.Environment = map[string]string{}
	}
	for k, v := range map[string]string{
		"PATH":          "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt",
	} {
		if _, found := ic.Environment[k]; !found {
			ic.Environment[k] = v
		}
	}
	envs := []string{}
	for k, v := range ic.Environment {
		envs = append(envs, fmt.Sprintf("%s=%s", k, v))
	}
	sort.Strings(envs)
	cfg.Config.Env = envs

	if ic.Accounts.RunAs != "" {
		cfg.Config.User = ic.Accounts.RunAs
	}

	if ic.StopSignal != "" {
		cfg.Config.StopSignal = ic.StopSignal
	}

	v1Image, err = mutate.ConfigFile(v1Image, cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to update %s config file: %w", imageType, err)
	}

	si := signed.Image(v1Image)
	return si, nil
}

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

// PostAttachSBOMsFromIndex attaches SBOMs to an already published index and all of the referenced images
func PostAttachSBOMsFromIndex(ctx context.Context, idx oci.SignedImageIndex, sboms []types.SBOM,
	logger log.Logger, tags []string, remoteOpts ...remote.Option) error {
	manifest, err := idx.IndexManifest()
	if err != nil {
		return fmt.Errorf("failed to get index manifest: %w", err)
	}
	var g errgroup.Group
	for _, m := range manifest.Manifests {
		m := m
		g.Go(func() error {
			img, err := idx.SignedImage(m.Digest)
			if err != nil {
				return fmt.Errorf("failed to get image %s: %w", m.Digest, err)
			}
			if _, err := PostAttachSBOM(
				ctx, img, sboms, m.Platform, logger, tags, remoteOpts...,
			); err != nil {
				return fmt.Errorf("attaching sboms to %s image: %w", m.Platform.String(), err)
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return err
	}

	if _, err := PostAttachSBOM(
		ctx, idx, sboms, nil, logger, tags, remoteOpts...,
	); err != nil {
		return fmt.Errorf("attaching sboms to index: %w", err)
	}
	return nil
}

// PostAttachSBOM attaches the sboms to an already published image
func PostAttachSBOM(ctx context.Context, si oci.SignedEntity, sboms []types.SBOM,
	platform *v1.Platform, logger log.Logger, tags []string, remoteOpts ...remote.Option) (oci.SignedEntity, error) {
	var err2 error
	if si, err2 = attachSBOM(si, sboms, platform, logger); err2 != nil {
		return nil, err2
	}
	var g errgroup.Group
	for _, tag := range tags {
		ref, err := name.ParseReference(tag)
		if err != nil {
			return nil, fmt.Errorf("parsing reference: %w", err)
		}
		// Write any attached SBOMs/signatures.
		wp := writePeripherals(ref, logger, remoteOpts...)
		g.Go(func() error {
			return wp(ctx, si)
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return si, nil
}

func attachSBOM(
	si oci.SignedEntity, sboms []types.SBOM,
	platform *v1.Platform, logger log.Logger,
) (oci.SignedEntity, error) {
	var mt ggcrtypes.MediaType
	var path string

	// get the index of the item
	var (
		h   v1.Hash
		err error
	)
	platformName := "index"
	if platform != nil {
		platformName = platform.String()
	}
	if i, ok := si.(oci.SignedImage); ok {
		h, err = i.Digest()
	} else if ii, ok := si.(oci.SignedImageIndex); ok {
		h, err = ii.Digest()
	} else {
		return nil, errors.New("unable to cast signed signedentity as image or index")
	}
	if err != nil {
		return nil, fmt.Errorf("unable to get digest for signed item: %w", err)
	}

	// find the sbom for use
	var matched []types.SBOM
	for _, s := range sboms {
		if s.Digest != h {
			continue
		}
		if (s.Arch == "" && platform == nil) || types.ParseArchitecture(s.Arch).ToOCIPlatform().String() == platform.String() {
			matched = append(matched, s)
		}
	}
	if len(matched) == 0 {
		return nil, fmt.Errorf("unable to find sbom for digest %s and platform %s", h, platformName)
	}

	switch matched[0].Format {
	case "spdx":
		mt = ctypes.SPDXJSONMediaType
	case "cyclonedx":
		mt = ctypes.CycloneDXJSONMediaType
	case "idb":
		mt = "application/vnd.apko.installed-db"
	default:
		return nil, fmt.Errorf("unsupported SBOM format: %s", matched[0].Format)
	}
	if len(matched) > 1 {
		// When we have multiple formats, warn that we're picking the first.
		logger.Warnf("multiple SBOM formats requested, uploading SBOM with media type: %s", mt)
	}
	path = matched[0].Path

	sbom, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading sbom: %w", err)
	}

	f, err := static.NewFile(sbom, static.WithLayerMediaType(mt))
	if err != nil {
		return nil, err
	}
	var aterr error
	if i, ok := si.(oci.SignedImage); ok {
		si, aterr = ocimutate.AttachFileToImage(i, "sbom", f)
	} else if ii, ok := si.(oci.SignedImageIndex); ok {
		si, aterr = ocimutate.AttachFileToImageIndex(ii, "sbom", f)
	} else {
		return nil, errors.New("unable to cast signed entity as image or index")
	}
	if aterr != nil {
		return nil, fmt.Errorf("attaching file to image: %w", aterr)
	}

	return si, nil
}

func BuildImageTarballFromLayer(imageRef string, layer v1.Layer, outputTarGZ string, ic types.ImageConfiguration, logger log.Logger, opts options.Options) error {
	v1Image, err := BuildImageFromLayer(layer, ic, opts.SourceDateEpoch, opts.Arch, logger)
	if err != nil {
		return err
	}

	if v1Image == nil {
		return errors.New("image build from layer returned nil")
	}
	imgRefTag, err := name.NewTag(imageRef)
	if err != nil {
		return fmt.Errorf("unable to validate image reference tag: %w", err)
	}

	if err := v1tar.WriteToFile(outputTarGZ, imgRefTag, v1Image); err != nil {
		return fmt.Errorf("unable to write image to disk: %w", err)
	}

	logger.Printf("output image file to %s", outputTarGZ)
	return nil
}

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

func PublishImage(ctx context.Context, image oci.SignedImage, local, shouldPushTags bool, logger log.Logger, tags []string, remoteOpts ...remote.Option) (name.Digest, error) {
	h, err := image.Digest()
	if err != nil {
		return name.Digest{}, fmt.Errorf("failed to compute digest: %w", err)
	}

	digest := name.Digest{}
	if shouldPushTags {
		for _, tag := range tags {
			logger.Printf("publishing image tag %v", tag)
			digest, err = publishTagFromImage(ctx, image, tag, h, local, logger, remoteOpts...)
			if err != nil {
				return name.Digest{}, err
			}
		}
	} else {
		logger.Printf("publishing image without tag (digest only)")
		digestOnly := fmt.Sprintf("%s@%s", strings.Split(tags[0], ":")[0], h.String())
		digest, err = publishTagFromImage(ctx, image, digestOnly, h, local, logger, remoteOpts...)
		if err != nil {
			return name.Digest{}, err
		}
	}

	return digest, nil
}

func PublishImageFromLayer(ctx context.Context, layer v1.Layer, ic types.ImageConfiguration, created time.Time, arch types.Architecture, logger log.Logger, local, shouldPushTags bool, tags []string, remoteOpts ...remote.Option) (name.Digest, oci.SignedImage, error) {
	v1Image, err := BuildImageFromLayer(layer, ic, created, arch, logger)
	if err != nil {
		return name.Digest{}, nil, err
	}

	h, err := v1Image.Digest()
	if err != nil {
		return name.Digest{}, nil, fmt.Errorf("failed to compute digest: %w", err)
	}

	digest := name.Digest{}
	if shouldPushTags {
		for _, tag := range tags {
			logger.Printf("publishing image tag %v", tag)
			digest, err = publishTagFromImage(ctx, v1Image, tag, h, local, logger, remoteOpts...)
			if err != nil {
				return name.Digest{}, nil, err
			}
		}
	} else {
		logger.Printf("publishing image without tag (digest only)")
		digestOnly := fmt.Sprintf("%s@%s", strings.Split(tags[0], ":")[0], h.String())
		digest, err = publishTagFromImage(ctx, v1Image, digestOnly, h, local, logger, remoteOpts...)
		if err != nil {
			return name.Digest{}, nil, err
		}
	}

	return digest, v1Image, nil
}

// GenerateIndex generates an OCI image index from the given image configurations. The index is stored in memory.
func GenerateIndex(ctx context.Context, ic types.ImageConfiguration, imgs map[types.Architecture]oci.SignedImage) (name.Digest, oci.SignedImageIndex, error) {
	return generateIndexWithMediaType(ggcrtypes.OCIImageIndex, ic, imgs)
}
func GenerateDockerIndex(ctx context.Context, ic types.ImageConfiguration, imgs map[types.Architecture]oci.SignedImage) (name.Digest, oci.SignedImageIndex, error) {
	return generateIndexWithMediaType(ggcrtypes.DockerManifestList, ic, imgs)
}
func generateIndexWithMediaType(mediaType ggcrtypes.MediaType, _ types.ImageConfiguration, imgs map[types.Architecture]oci.SignedImage) (name.Digest, oci.SignedImageIndex, error) {
	idx := signed.ImageIndex(mutate.IndexMediaType(empty.Index, mediaType))
	archs := make([]types.Architecture, 0, len(imgs))
	for arch := range imgs {
		archs = append(archs, arch)
	}
	sort.Slice(archs, func(i, j int) bool {
		return archs[i].String() < archs[j].String()
	})
	for _, arch := range archs {
		img := imgs[arch]
		mt, err := img.MediaType()
		if err != nil {
			return name.Digest{}, nil, fmt.Errorf("failed to get mediatype: %w", err)
		}

		h, err := img.Digest()
		if err != nil {
			return name.Digest{}, nil, fmt.Errorf("failed to compute digest: %w", err)
		}

		size, err := img.Size()
		if err != nil {
			return name.Digest{}, nil, fmt.Errorf("failed to compute size: %w", err)
		}

		idx = ocimutate.AppendManifests(idx, ocimutate.IndexAddendum{
			Add: img,
			Descriptor: v1.Descriptor{
				MediaType: mt,
				Digest:    h,
				Size:      size,
				Platform:  arch.ToOCIPlatform(),
			},
		})
	}
	h, err := idx.Digest()
	if err != nil {
		return name.Digest{}, idx, err
	}
	digest, err := name.NewDigest(fmt.Sprintf("%s@%s", "image", h.String()))
	return digest, idx, err
}

func PublishIndex(ctx context.Context, idx oci.SignedImageIndex, logger log.Logger, local bool, shouldPushTags bool, tags []string, remoteOpts ...remote.Option) (name.Digest, oci.SignedImageIndex, error) {
	// TODO(jason): Also set annotations on the index. ggcr's
	// pkg/v1/mutate.Annotations will drop the interface methods from
	// oci.SignedImageIndex, so we may need to reimplement
	// mutate.Annotations in ocimutate to keep it for now.

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
	if shouldPushTags {
		for _, tag := range tags {
			logger.Printf("publishing index tag %v", tag)
			digest, err = publishTagFromIndex(ctx, idx, tag, h, logger, remoteOpts...)
			if err != nil {
				return name.Digest{}, nil, err
			}
		}
	} else {
		logger.Printf("publishing index without tag (digest only)")
		digestOnly := fmt.Sprintf("%s@%s", strings.Split(tags[0], ":")[0], h.String())
		digest, err = publishTagFromIndex(ctx, idx, digestOnly, h, logger, remoteOpts...)
		if err != nil {
			return name.Digest{}, nil, err
		}
	}

	return digest, idx, nil
}

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

// BuildIndex builds a self-container tar.gz file containing the index and its individual images for all architectures.
// Returns the digest and the path to the combined tar.gz.
func BuildIndex(outfile string, idx oci.SignedImageIndex, tags []string, logger log.Logger) (name.Digest, error) {
	tagsToImages := make(map[name.Tag]v1.Image)
	var imgs = make([]oci.SignedImage, 0)
	manifest, err := idx.IndexManifest()
	if err != nil {
		return name.Digest{}, fmt.Errorf("failed to get index manifest: %w", err)
	}

	var parsedTags = make([]name.Tag, 0)
	for _, tag := range tags {
		parsedTag, err := name.NewTag(tag)
		if err != nil {
			return name.Digest{}, fmt.Errorf("failed to parse tag %s: %w", tag, err)
		}
		parsedTags = append(parsedTags, parsedTag)
	}
	for _, m := range manifest.Manifests {
		arch := m.Platform.Architecture
		img, err := idx.SignedImage(m.Digest)
		if err != nil {
			return name.Digest{}, fmt.Errorf("failed to get image for manifest %s: %w", m.Digest, err)
		}
		imgs = append(imgs, img)
		for _, ref := range parsedTags {
			ref, err = name.NewTag(fmt.Sprintf("%s-%s", ref.Name(), strings.ReplaceAll(arch, "/", "_")))
			if err != nil {
				return name.Digest{}, fmt.Errorf("failed to get image for manifest %s: %w", m.Digest, err)
			}
			tagsToImages[ref] = img
		}
	}

	f, err := os.OpenFile(outfile, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return name.Digest{}, fmt.Errorf("failed to open outfile %s: %w", outfile, err)
	}
	defer f.Close()
	h, err := idx.Digest()
	if err != nil {
		return name.Digest{}, err
	}
	digest, err := name.NewDigest(fmt.Sprintf("%s@%s", "image", h.String()))
	if err != nil {
		return name.Digest{}, err
	}
	if err := v1tar.MultiWrite(tagsToImages, f); err != nil {
		return name.Digest{}, fmt.Errorf("failed to write index to tgz: %w", err)
	}

	// to append to a tar archive, you need to find the last file in the archive
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return name.Digest{}, fmt.Errorf("failed to seek beginning of file: %w", err)
	}

	tr := tar.NewReader(f)
	var lastFileSize, lastStreamPos int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return name.Digest{}, fmt.Errorf("failed to read tar header: %w", err)
		}
		lastStreamPos, err = f.Seek(0, io.SeekCurrent)
		if err != nil {
			return name.Digest{}, fmt.Errorf("failed to get current position in file: %w", err)
		}
		lastFileSize = hdr.Size
	}
	const blockSize = 512
	newOffset := lastStreamPos + lastFileSize
	newOffset += blockSize - (newOffset % blockSize) // shift to next-nearest block boundary
	if _, err := f.Seek(newOffset, io.SeekStart); err != nil {
		return name.Digest{}, fmt.Errorf("failed to seek to new offset: %w", err)
	}

	tw := tar.NewWriter(f)
	defer tw.Close()

	// write each manifest file
	for _, img := range imgs {
		raw, err := img.RawManifest()
		if err != nil {
			return name.Digest{}, fmt.Errorf("failed to get raw manifest: %w", err)
		}
		dig, err := img.Digest()
		if err != nil {
			return name.Digest{}, fmt.Errorf("failed to get digest for manifest: %w", err)
		}
		if err := tw.WriteHeader(&tar.Header{
			Name: dig.String(),
			Size: int64(len(raw)),
			Mode: 0o644,
		}); err != nil {
			return name.Digest{}, fmt.Errorf("failed to write manifest header: %w", err)
		}
		if _, err := tw.Write(raw); err != nil {
			return name.Digest{}, fmt.Errorf("failed to write manifest: %w", err)
		}
	}

	// Write the index.json
	index, err := idx.RawManifest()
	if err != nil {
		return name.Digest{}, fmt.Errorf("failed to get raw index: %w", err)
	}
	if err := tw.WriteHeader(&tar.Header{
		Name: "index.json",
		Size: int64(len(index)),
		Mode: 0o644,
	}); err != nil {
		return name.Digest{}, fmt.Errorf("failed to write index.json header: %w", err)
	}
	if _, err := tw.Write(index); err != nil {
		return name.Digest{}, fmt.Errorf("failed to write index.json: %w", err)
	}

	return digest, nil
}

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

func humanReadableImageType(mediaType ggcrtypes.MediaType) string {
	switch mediaType {
	case ggcrtypes.DockerLayer:
		return "Docker"
	case ggcrtypes.OCILayer:
		return "OCI"
	}
	return "unknown"
}
