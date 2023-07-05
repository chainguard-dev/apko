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
	"errors"
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	ggcrtypes "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/cosign/v2/pkg/oci"
	ocimutate "github.com/sigstore/cosign/v2/pkg/oci/mutate"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	ctypes "github.com/sigstore/cosign/v2/pkg/types"
	"go.opentelemetry.io/otel"
	"golang.org/x/sync/errgroup"

	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/log"
)

// PostAttachSBOMsFromIndex attaches SBOMs to an already published index and all of the referenced images
func PostAttachSBOMsFromIndex(ctx context.Context, idx oci.SignedImageIndex, sboms []types.SBOM,
	logger log.Logger, tags []string, remoteOpts ...remote.Option) error {
	ctx, span := otel.Tracer("apko").Start(ctx, "PostAttachSBOMsFromIndex")
	defer span.End()

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

// PostAttachSBOM attaches the sboms to a single already published image
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

// attachSBOM does the actual attachment of one or more SBOMs to a single image or index.
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
