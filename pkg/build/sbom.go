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
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sort"
	"time"

	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/options"
	"chainguard.dev/apko/pkg/sbom"
	"chainguard.dev/apko/pkg/sbom/generator"
	soptions "chainguard.dev/apko/pkg/sbom/options"

	"github.com/chainguard-dev/clog"
	apkfs "github.com/chainguard-dev/go-apk/pkg/fs"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	ggcrtypes "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"go.opentelemetry.io/otel"
	khash "sigs.k8s.io/release-utils/hash"
)

func newSBOM(ctx context.Context, fsys apkfs.FullFS, o options.Options, ic types.ImageConfiguration, bde time.Time) soptions.Options {
	log := clog.FromContext(ctx)
	sopt := sbom.DefaultOptions
	sopt.FS = fsys
	sopt.FileName = fmt.Sprintf("sbom-%s", o.Arch.ToAPK())

	// Parse the image reference
	if len(o.Tags) > 0 {
		tag, err := name.NewTag(o.Tags[0])
		if err == nil {
			sopt.ImageInfo.Tag = tag.TagStr()
			sopt.ImageInfo.Name = tag.String()
		} else {
			log.Errorf("%s parsing tag %s, ignoring", o.Tags[0], err)
		}
	}

	sopt.ImageInfo.SourceDateEpoch = bde
	sopt.Formats = o.SBOMFormats
	sopt.ImageInfo.VCSUrl = ic.VCSUrl
	sopt.ImageInfo.ImageMediaType = ggcrtypes.OCIManifestSchema1

	sopt.OutputDir = o.TempDir()
	if o.SBOMPath != "" {
		sopt.OutputDir = o.SBOMPath
	}

	return sopt
}

func (bc *Context) GenerateImageSBOM(ctx context.Context, arch types.Architecture, img oci.SignedImage) ([]types.SBOM, error) {
	log := clog.New(slog.Default().Handler()).With("arch", arch.ToAPK())
	ctx = clog.WithLogger(ctx, log)

	_, span := otel.Tracer("apko").Start(ctx, "GenerateImageSBOM")
	defer span.End()

	if !bc.WantSBOM() {
		log.Warnf("skipping SBOM generation")
		return nil, nil
	}

	bde, err := bc.GetBuildDateEpoch()
	if err != nil {
		return nil, fmt.Errorf("computing build date epoch: %w", err)
	}

	m, err := img.Manifest()
	if err != nil {
		return nil, fmt.Errorf("getting %s manifest: %w", arch, err)
	}

	if bc.baseimg == nil && len(m.Layers) != 1 {
		return nil, fmt.Errorf("unexpected layers in %s manifest: %d", arch, len(m.Layers))
	}

	s := newSBOM(ctx, bc.fs, bc.o, bc.ic, bde)
	log.Debug("Generating image SBOM")

	s.ImageInfo.LayerDigest = m.Layers[0].Digest.String()

	info, err := sbom.ReadReleaseData(bc.fs)
	if err != nil {
		return nil, fmt.Errorf("reading release data: %w", err)
	}

	s.OS.Name = info.Name
	s.OS.ID = info.ID
	s.OS.Version = info.VersionID

	pkgs, err := bc.apk.GetInstalled()
	if err != nil {
		return nil, fmt.Errorf("reading apk package index: %w", err)
	}

	s.Packages = pkgs

	// Get the image digest
	h, err := img.Digest()
	if err != nil {
		return nil, fmt.Errorf("getting %s image digest: %w", arch, err)
	}

	s.ImageInfo.ImageDigest = h.String()
	s.ImageInfo.Arch = arch

	var sboms = make([]types.SBOM, 0)
	generators := generator.Generators(bc.fs)
	for _, format := range s.Formats {
		gen, ok := generators[format]
		if !ok {
			return nil, fmt.Errorf("unable to generate sboms: no generator available for format %s", format)
		}

		filename := filepath.Join(s.OutputDir, s.FileName+"."+gen.Ext())
		if err := gen.Generate(&s, filename); err != nil {
			return nil, fmt.Errorf("generating %s sbom: %w", format, err)
		}
		sboms = append(sboms, types.SBOM{
			Path:   filename,
			Format: format,
			Arch:   arch.String(),
			Digest: h,
		})
	}
	return sboms, nil
}

func GenerateIndexSBOM(ctx context.Context, o options.Options, ic types.ImageConfiguration, indexDigest name.Digest, imgs map[types.Architecture]oci.SignedImage) ([]types.SBOM, error) {
	log := clog.FromContext(ctx)
	_, span := otel.Tracer("apko").Start(ctx, "GenerateIndexSBOM")
	defer span.End()

	if len(o.SBOMFormats) == 0 {
		log.Warn("skipping SBOM generation")
		return nil, nil
	}

	s := newSBOM(ctx, nil, o, ic, o.SourceDateEpoch)
	log.Debug("Generating index SBOM")

	// Add the image digest
	h, err := v1.NewHash(indexDigest.DigestStr())
	if err != nil {
		return nil, errors.New("getting index hash")
	}
	s.ImageInfo.IndexDigest = h

	s.ImageInfo.IndexMediaType = ggcrtypes.OCIImageIndex

	// Make sure we have a determinstic for iterating over imgs.
	archs := make([]types.Architecture, 0, len(imgs))
	for arch := range imgs {
		archs = append(archs, arch)
	}
	sort.Slice(archs, func(i, j int) bool {
		return archs[i].String() < archs[j].String()
	})

	generators := generator.Generators(nil)
	var sboms = make([]types.SBOM, 0, len(generators))
	for _, format := range s.Formats {
		gen, ok := generators[format]
		if !ok {
			return nil, fmt.Errorf("unable to generate sboms: no generator available for format %s", format)
		}

		archImageInfos := make([]soptions.ArchImageInfo, 0, len(archs))
		for _, arch := range archs {
			i := imgs[arch]
			sbomHash, err := khash.SHA256ForFile(filepath.Join(s.OutputDir, fmt.Sprintf("sbom-%s.%s", arch.ToAPK(), gen.Ext())))
			if err != nil {
				return nil, fmt.Errorf("checksumming %s SBOM: %w", arch, err)
			}

			d, err := i.Digest()
			if err != nil {
				return nil, fmt.Errorf("getting arch image digest: %w", err)
			}

			info := soptions.ArchImageInfo{
				Digest:     d,
				Arch:       arch,
				SBOMDigest: sbomHash,
			}
			archImageInfos = append(archImageInfos, info)
		}
		s.ImageInfo.Images = archImageInfos

		filename := filepath.Join(s.OutputDir, "sbom-index."+gen.Ext())
		if err := gen.GenerateIndex(&s, filename); err != nil {
			return nil, fmt.Errorf("generating %s sbom: %w", format, err)
		}
		sboms = append(sboms, types.SBOM{
			Path:   filename,
			Format: format,
			Digest: h,
		})
	}

	return sboms, nil
}
