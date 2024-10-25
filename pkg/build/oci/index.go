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
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	v1tar "github.com/google/go-containerregistry/pkg/v1/tarball"
	ggcrtypes "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/cosign/v2/pkg/oci"
	ocimutate "github.com/sigstore/cosign/v2/pkg/oci/mutate"
	"github.com/sigstore/cosign/v2/pkg/oci/signed"
	"go.opentelemetry.io/otel"

	"chainguard.dev/apko/pkg/build/types"
)

// GenerateIndex generates an OCI image index from the given imgs. The index type
// will be "application/vnd.oci.image.index.v1+json".
// The index is stored in memory.
func GenerateIndex(ctx context.Context, ic types.ImageConfiguration, imgs map[types.Architecture]oci.SignedImage, created time.Time) (name.Digest, oci.SignedImageIndex, error) {
	_, span := otel.Tracer("apko").Start(ctx, "GenerateIndex")
	defer span.End()

	return generateIndexWithMediaType(ggcrtypes.OCIImageIndex, ic, imgs, created)
}

// GenerateDockerIndex generates a docker multi-arch manifest from the given imgs. The index type
// will be "application/vnd.docker.distribution.manifest.list.v2+json".
// The index is stored in memory.
func GenerateDockerIndex(ctx context.Context, ic types.ImageConfiguration, imgs map[types.Architecture]oci.SignedImage, created time.Time) (name.Digest, oci.SignedImageIndex, error) {
	return generateIndexWithMediaType(ggcrtypes.DockerManifestList, ic, imgs, created)
}

// generateIndexWithMediaType generates an index or docker manifest list from the given imgs. The index type
// is provided by the `mediaType` parameter.
func generateIndexWithMediaType(mediaType ggcrtypes.MediaType, ic types.ImageConfiguration, imgs map[types.Architecture]oci.SignedImage, created time.Time) (name.Digest, oci.SignedImageIndex, error) {
	// If annotations are set and we're using the OCI mediaType, set annotations on the index.
	annotations := ic.GetAnnotations()
	if mediaType == ggcrtypes.OCIImageIndex {
		if ic.VCSUrl != "" {
			if url, hash, ok := strings.Cut(ic.VCSUrl, "@"); ok {
				annotations["org.opencontainers.image.source"] = url
				annotations["org.opencontainers.image.revision"] = hash
			}
		}
		annotations["org.opencontainers.image.created"] = created.Format(time.RFC3339)
	}

	idx := signed.ImageIndex(
		mutate.IndexMediaType(
			mutate.Annotations(empty.Index, annotations).(v1.ImageIndex),
			mediaType),
	)
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

// BuildIndex builds a self-contained tar.gz file containing the index and its individual images for all architectures.
// Returns the digest and the path to the combined tar.gz.
func BuildIndex(outfile string, idx oci.SignedImageIndex, tags []string) (name.Digest, error) {
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
