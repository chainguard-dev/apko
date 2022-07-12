// Copyright 2022 Chainguard, Inc.
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

package options

import (
	"path/filepath"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	ggcrtypes "github.com/google/go-containerregistry/pkg/v1/types"
	"gitlab.alpinelinux.org/alpine/go/pkg/repository"

	"chainguard.dev/apko/pkg/build/types"
)

type Options struct {
	OS OSInfo

	ImageInfo ImageInfo

	// Working directory,inherited from buid context
	WorkDir string

	// The reference of the generated image. Used for naming and purls
	ImageReference string

	// OutputDir is the directory where the sboms will be written
	OutputDir string

	// FileName is the base name for the sboms, the proper extension will get appended
	FileName string

	// Formats dictates which SBOM formats we will output
	Formats []string

	// Packages is alist of packages which will be listed in the SBOM
	Packages []*repository.Package
}

type OSInfo struct {
	Name    string
	ID      string
	Version string
}

type ImageInfo struct {
	Reference       string
	Tag             string
	Name            string
	Repository      string
	LayerDigest     string
	ImageDigest     string
	VCSUrl          string
	IndexMediaType  ggcrtypes.MediaType
	ImageMediaType  ggcrtypes.MediaType
	IndexDigest     v1.Hash
	Images          []ArchImageInfo
	Arch            types.Architecture
	SourceDateEpoch time.Time
}

type ArchImageInfo struct {
	Digest     v1.Hash
	Arch       types.Architecture
	SBOMDigest string
}

// ImagePurlName returns a name to represent the image in a purl
func (o *Options) ImagePurlName() string {
	repoName := "image"
	if o.ImageInfo.Name != "" {
		ref, err := name.ParseReference(o.ImageInfo.Name)
		if err != nil {
			return repoName
		}
		repoName = filepath.Base(ref.Context().RepositoryStr())
	}
	return repoName
}

// IndexPurlName returns a name to refer to the image index in purls
func (o *Options) IndexPurlName() string {
	repoName := o.ImagePurlName()
	if repoName == "image" {
		return "index"
	}
	return repoName
}

// ImagePurlQualifiers returns the qualifiers for an image, the extra
// data that goes into the purl quey string
func (o *Options) ImagePurlQualifiers() (qualifiers map[string]string) {
	qualifiers = map[string]string{}
	if o.ImageInfo.Repository != "" {
		qualifiers["repository_url"] = escapeQualifier(o.ImageInfo.Repository)
	}
	if o.ImageInfo.Arch.String() != "" {
		qualifiers["arch"] = escapeQualifier(o.ImageInfo.Arch.ToOCIPlatform().Architecture)
	}
	// This should be "linux" always
	if o.ImageInfo.Arch.ToOCIPlatform().OS != "" {
		qualifiers["os"] = escapeQualifier(o.ImageInfo.Arch.ToOCIPlatform().OS)
	}
	if o.ImageInfo.ImageMediaType != "" {
		qualifiers["mediaType"] = escapeQualifier(string(o.ImageInfo.ImageMediaType))
	}
	return qualifiers
}

// This function is here while a fix in the purl library gets merged
// ref: https://github.com/package-url/packageurl-go/pull/22
func escapeQualifier(in string) string {
	return strings.ReplaceAll(in, "+", "%26")
}

// LayerPurlQualifiers reurns the qualifiers for the purl, they are based
// on the image with the corresponding mediatype
func (o *Options) LayerPurlQualifiers() (qualifiers map[string]string) {
	qualifiers = o.ImagePurlQualifiers()
	switch o.ImageInfo.ImageMediaType {
	case ggcrtypes.OCIManifestSchema1:
		qualifiers["mediaType"] = escapeQualifier(string(ggcrtypes.OCILayer))
	case ggcrtypes.DockerManifestSchema2:
		qualifiers["mediaType"] = escapeQualifier(string(ggcrtypes.DockerLayer))
	default:
		qualifiers["mediaType"] = ""
	}
	return qualifiers
}

// IndexPurlQualifiers returns the qualifiers for the multiarch index
func (o *Options) IndexPurlQualifiers() map[string]string {
	qualifiers := map[string]string{}
	if o.ImageInfo.Repository != "" {
		qualifiers["repository_url"] = escapeQualifier(o.ImageInfo.Repository)
	}
	if o.ImageInfo.IndexMediaType != "" {
		qualifiers["mediaType"] = escapeQualifier(string(o.ImageInfo.IndexMediaType))
	}
	return qualifiers
}

// ArchImagePurlQualifiers returns the details
func (o *Options) ArchImagePurlQualifiers(aii *ArchImageInfo) map[string]string {
	qualifiers := o.IndexPurlQualifiers()
	qualifiers["arch"] = aii.Arch.ToOCIPlatform().Architecture
	qualifiers["os"] = aii.Arch.ToOCIPlatform().OS
	switch o.ImageInfo.IndexMediaType {
	case ggcrtypes.OCIImageIndex:
		qualifiers["mediaType"] = escapeQualifier(string(ggcrtypes.OCIManifestSchema1))
	case ggcrtypes.DockerManifestList:
		qualifiers["mediaType"] = escapeQualifier(string(ggcrtypes.DockerManifestSchema2))
	default:
		qualifiers["mediaType"] = ""
	}
	return qualifiers
}
