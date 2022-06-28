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
	"time"
	"os"

	"chainguard.dev/apko/pkg/build/types"

	nested "github.com/antonfisher/nested-logrus-formatter"
	"github.com/sirupsen/logrus"
)

type Options struct {
	UseDockerMediaTypes bool
	WantSBOM            bool
	UseProot            bool
	WorkDir             string
	TarballPath         string
	Tags                []string
	SourceDateEpoch     time.Time
	SBOMPath            string
	SBOMFormats         []string
	ExtraKeyFiles       []string
	ExtraRepos          []string
	Arch                types.Architecture
	Log                 *logrus.Logger
}

var Default = Options{
	Log: &logrus.Logger{
		Out: os.Stderr,
		Formatter: &nested.Formatter{
			ShowFullLevel: true,
		},
		Hooks: make(logrus.LevelHooks),
		Level: logrus.DebugLevel,
	},
}

func (o *Options) Summarize() {
	o.Log.Printf("  working directory: %s", o.WorkDir)
	o.Log.Printf("  tarball path: %s", o.TarballPath)
	o.Log.Printf("  use proot: %t", o.UseProot)
	o.Log.Printf("  source date: %s", o.SourceDateEpoch)
	o.Log.Printf("  Docker mediatypes: %t", o.UseDockerMediaTypes)
	o.Log.Printf("  SBOM output path: %s", o.SBOMPath)
	o.Log.Printf("  arch: %v", o.Arch.ToAPK())
}

func (o *Options) Logger() *logrus.Entry {
	return o.Log.WithFields(logrus.Fields{"arch": o.Arch.ToAPK()})
}
