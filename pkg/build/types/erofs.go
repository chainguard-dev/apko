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

package types

// EROFS media types and annotation keys from the draft
// erofs/erofs-image-spec (PR #1). Both the writer (pkg/build) and the
// reader/mount tools (pkg/erofsmount) reference these; centralizing them
// here keeps the two sides honest as the spec evolves.
const (
	// ErofsLayerMediaType is the manifest mediaType for an EROFS filesystem
	// layer blob (raw or internally compressed).
	ErofsLayerMediaType = "application/vnd.erofs"
	// ErofsRoleAnnotation is the layer-descriptor annotation key that names
	// the layer's overlayfs role per spec §3.8.
	ErofsRoleAnnotation = "org.erofs.role"
	// ErofsRoleOverlayLower marks a layer as an overlay lowerdir. Per spec
	// §3.8 rule 1, every non-final layer carries this; the final layer
	// carries no role annotation.
	ErofsRoleOverlayLower = "overlay-lower"
	// ErofsUncompressedDigestAnnotation is the layer-descriptor annotation
	// holding the SHA-256 of the equivalent uncompressed EROFS image. Equals
	// the layer's DiffID in the OCI image config's rootfs.diff_ids.
	ErofsUncompressedDigestAnnotation = "org.erofs.uncompressed-digest"
)
