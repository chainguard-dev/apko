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
// erofs/erofs-image-spec (spec.md). Both the writer (pkg/build) and the
// reader tools (pkg/erofsmount) reference these; centralizing them here keeps
// the two sides honest as the spec evolves.
const (
	// ErofsLayerMediaType is the manifest mediaType for an EROFS filesystem
	// layer blob (raw or internally compressed).
	ErofsLayerMediaType = "application/vnd.erofs"
	// ErofsRoleAnnotation is the layer-descriptor annotation key that names
	// the layer's composition role. It is OPTIONAL on any layer (spec §2.3);
	// an absent role means the layer is part of the overlay stack, or is the
	// whole root filesystem in the single-layer case.
	ErofsRoleAnnotation = "org.erofs.role"
	// ErofsRoleOverlayLower marks a layer as an overlayfs lowerdir. Spec §7
	// step 1 treats this and an absent role identically, at any position.
	ErofsRoleOverlayLower = "overlay-lower"
	// ErofsRoleOverlayData marks a layer supplied as an overlayfs data-only
	// lower (spec §2.4). apko neither writes nor reads these.
	ErofsRoleOverlayData = "overlay-data"
	// ErofsRoleDevice marks a layer used as a raw byte source for EROFS
	// multi-device addressing (spec §2.4). apko neither writes nor reads
	// these.
	ErofsRoleDevice = "device"
)
