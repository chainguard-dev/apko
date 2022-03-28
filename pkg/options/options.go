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
	"log"
	"time"

	"chainguard.dev/apko/pkg/build/types"
)

type Options struct {
	WantSBOM        bool
	UseProot        bool
	WorkDir         string
	TarballPath     string
	Tags            []string
	SourceDateEpoch time.Time
	SBOMPath        string
	SBOMFormats     []string
	ExtraKeyFiles   []string
	ExtraRepos      []string
	Arch            types.Architecture
	Log             *log.Logger
}

var Default = Options{
	Log: log.New(log.Writer(), "apko (early): ", log.LstdFlags|log.Lmsgprefix),
}

func (o *Options) Summarize() {
	o.Log.Printf("  working directory: %s", o.WorkDir)
	o.Log.Printf("  tarball path: %s", o.TarballPath)
	o.Log.Printf("  use proot: %t", o.UseProot)
	o.Log.Printf("  source date: %s", o.SourceDateEpoch)
	o.Log.Printf("  SBOM output path: %s", o.SBOMPath)
	o.Log.Printf("  arch: %v", o.Arch.ToAPK())
}
