// Copyright 2026 Chainguard, Inc.
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

package erofsmount

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	ocitypes "github.com/google/go-containerregistry/pkg/v1/types"

	"chainguard.dev/apko/pkg/build/types"
)

const annotationRefName = "org.opencontainers.image.ref.name"

// LayerRef points at one EROFS layer blob on disk along with its descriptor
// metadata.
type LayerRef struct {
	BlobPath    string
	Digest      string
	MediaType   string
	Annotations map[string]string
	// Role is the value of the org.erofs.role annotation, "" for the final
	// (top) layer.
	Role string
}

// ReadOCILayers loads an OCI image layout, selects a manifest, and returns its
// EROFS layer references in manifest order (bottom-up — caller is responsible
// for reversing the order when feeding overlayfs lowerdirs).
//
// tag, when non-empty, picks the manifest whose
// org.opencontainers.image.ref.name annotation matches. When empty, exactly
// one image manifest must be selectable.
//
// arch is used to disambiguate multi-arch indexes. "" or "host" means the
// process's runtime.GOARCH.
func ReadOCILayers(ociDir, tag, arch string) ([]LayerRef, error) {
	if arch == "" || arch == "host" {
		arch = runtime.GOARCH
	}

	idx, err := layout.ImageIndexFromPath(ociDir)
	if err != nil {
		return nil, fmt.Errorf("open oci layout %s: %w", ociDir, err)
	}

	img, err := selectImage(idx, tag, arch)
	if err != nil {
		return nil, fmt.Errorf("oci layout %s: %w", ociDir, err)
	}

	manifest, err := img.Manifest()
	if err != nil {
		return nil, fmt.Errorf("oci layout %s: read manifest: %w", ociDir, err)
	}
	if len(manifest.Layers) == 0 {
		return nil, fmt.Errorf("oci layout %s: image has no layers", ociDir)
	}

	refs := make([]LayerRef, 0, len(manifest.Layers))
	for i, desc := range manifest.Layers {
		if mt := string(desc.MediaType); mt != types.ErofsLayerMediaType {
			// A "+codec" suffix names an externally compressed EROFS layer:
			// really an EROFS image, just not one we can read without
			// decompressing it first. Saying "not an EROFS image" would be
			// wrong and unhelpful.
			if codec, ok := strings.CutPrefix(mt, types.ErofsLayerMediaType+"+"); ok && codec != "" {
				return nil, fmt.Errorf("layer %d is a %s-compressed EROFS layer (mediaType %q), which apko cannot read yet; see https://github.com/chainguard-dev/apko/pull/2406", i, codec, mt)
			}
			return nil, fmt.Errorf("layer %d has mediaType %q; expected %q (this command only handles EROFS images)", i, mt, types.ErofsLayerMediaType)
		}
		// org.erofs.role is OPTIONAL on any layer (spec §2.3), and §7 step 1
		// classifies both "overlay-lower" and an absent role as overlay lowers
		// at any position -- so both are accepted here, wherever they appear.
		// The other two roles name compositions we don't implement; say so
		// rather than calling a conformant image malformed.
		switch role := desc.Annotations[types.ErofsRoleAnnotation]; role {
		case "", types.ErofsRoleOverlayLower:
		case types.ErofsRoleDevice, types.ErofsRoleOverlayData:
			return nil, fmt.Errorf("layer %d has %s=%s, which is not supported yet (only overlay lowers are)", i, types.ErofsRoleAnnotation, role)
		default:
			return nil, fmt.Errorf("layer %d has unknown %s=%q", i, types.ErofsRoleAnnotation, role)
		}
		blob := filepath.Join(ociDir, "blobs", desc.Digest.Algorithm, desc.Digest.Hex)
		if _, err := os.Stat(blob); err != nil {
			return nil, fmt.Errorf("layer %d blob %s: %w", i, blob, err)
		}
		refs = append(refs, LayerRef{
			BlobPath:    blob,
			Digest:      desc.Digest.String(),
			MediaType:   string(desc.MediaType),
			Annotations: desc.Annotations,
			Role:        desc.Annotations[types.ErofsRoleAnnotation],
		})
	}

	// §3.8 rule 1 -- the last entry must be a mountable EROFS layer whose role
	// is absent or overlay-lower -- now holds by construction: every layer got
	// past the mediaType and role checks above.
	return refs, nil
}

// selectImage picks an image manifest from idx by tag and arch.
//
// If tag is set, manifests are filtered to those whose ref.name annotation
// matches; otherwise all are eligible. Among eligible manifests, nested
// indexes are unwrapped (recursing once) so multi-arch indexes resolve to a
// single per-arch image. arch then filters image manifests by Platform.
func selectImage(idx v1.ImageIndex, tag, arch string) (v1.Image, error) {
	manifest, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("read index manifest: %w", err)
	}

	eligible := manifest.Manifests
	if tag != "" {
		eligible = filterByRefName(manifest.Manifests, tag)
		if len(eligible) == 0 {
			return nil, fmt.Errorf("no manifest with %s=%q (available: %s)", annotationRefName, tag, availableTagsList(manifest.Manifests))
		}
	}

	// Unwrap a top-level nested OCIImageIndex once (apko's publish path
	// often emits one) — but only when no tag was given. With a tag, the
	// caller already pinpointed a manifest.
	if tag == "" && len(eligible) == 1 && eligible[0].MediaType == ocitypes.OCIImageIndex {
		child, err := idx.ImageIndex(eligible[0].Digest)
		if err != nil {
			return nil, fmt.Errorf("descend into nested index: %w", err)
		}
		return selectImage(child, "", arch)
	}

	// Filter to image manifests (drop any indexes).
	var images []v1.Descriptor
	for _, m := range eligible {
		switch m.MediaType {
		case ocitypes.OCIManifestSchema1, ocitypes.DockerManifestSchema2:
			images = append(images, m)
		}
	}
	if len(images) == 0 {
		return nil, fmt.Errorf("no image manifest in index (saw %d entries)", len(eligible))
	}

	// Filter by arch if either there are multiple candidates or the lone
	// candidate has a non-matching platform.
	var matches []v1.Descriptor
	for _, m := range images {
		if m.Platform == nil || m.Platform.Architecture == "" || m.Platform.Architecture == arch {
			matches = append(matches, m)
		}
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("no manifest for arch=%q (saw: %s)", arch, availableArchList(images))
	}
	if len(matches) > 1 {
		// There is no --tag flag; a tag is given as a SOURCE:TAG suffix.
		return nil, fmt.Errorf("multiple manifests match arch=%q; name a tag as SOURCE:TAG to disambiguate (available: %s)", arch, availableTagsList(images))
	}

	return idx.Image(matches[0].Digest)
}

func filterByRefName(ms []v1.Descriptor, tag string) []v1.Descriptor {
	var out []v1.Descriptor
	for _, m := range ms {
		if m.Annotations[annotationRefName] == tag {
			out = append(out, m)
		}
	}
	return out
}

func availableTagsList(ms []v1.Descriptor) string {
	var tags []string
	for _, m := range ms {
		if t := m.Annotations[annotationRefName]; t != "" {
			tags = append(tags, t)
		}
	}
	if len(tags) == 0 {
		return "(none set)"
	}
	return strings.Join(tags, ", ")
}

func availableArchList(ms []v1.Descriptor) string {
	var archs []string
	for _, m := range ms {
		if m.Platform != nil && m.Platform.Architecture != "" {
			archs = append(archs, m.Platform.Architecture)
		} else {
			archs = append(archs, "(none)")
		}
	}
	return strings.Join(archs, ", ")
}
