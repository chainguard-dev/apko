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
	Reference  string
	Tag        string
	Name       string
	Repository string
	Digest     string
	Arch       types.Architecture
}
