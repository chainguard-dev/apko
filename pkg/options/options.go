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

package options

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/log"
)

type Options struct {
	WithVCS                 bool               `json:"withVCS,omitempty"`
	TarballPath             string             `json:"tarballPath,omitempty"`
	Tags                    []string           `json:"tags,omitempty"`
	SourceDateEpoch         time.Time          `json:"sourceDateEpoch,omitempty"`
	SBOMPath                string             `json:"sbomPath,omitempty"`
	SBOMFormats             []string           `json:"sbomFormats,omitempty"`
	ExtraKeyFiles           []string           `json:"extraKeyFiles,omitempty"`
	ExtraRepos              []string           `json:"extraRepos,omitempty"`
	ExtraPackages           []string           `json:"extraPackages,omitempty"`
	Arch                    types.Architecture `json:"arch,omitempty"`
	TempDirPath             string             `json:"tempDirPath,omitempty"`
	PackageVersionTag       string             `json:"packageVersionTag,omitempty"`
	PackageVersionTagStem   bool               `json:"packageVersionTagStem,omitempty"`
	PackageVersionTagPrefix string             `json:"packageVersionTagPrefix,omitempty"`
	TagSuffix               string             `json:"tagSuffix,omitempty"`
	Local                   bool               `json:"local,omitempty"`
	CacheDir                string             `json:"cacheDir,omitempty"`
	Offline                 bool               `json:"offline,omitempty"`
	ResolvedFile            string             `json:"resolvedFile,omitempty"`

	Log log.Logger
}

var Default = Options{
	Log:             &log.Adapter{Out: io.Discard, Level: log.InfoLevel},
	Arch:            types.ParseArchitecture(runtime.GOARCH),
	SourceDateEpoch: time.Unix(0, 0).UTC(),
}

func (o *Options) Summarize(logger log.Logger) {
	b, err := json.MarshalIndent(o, "", "\t")
	if err != nil {
		logger.Errorf("error marshalling build options: %v", err)
	} else {
		logger.Printf("build options:\n%s", string(b))
	}
}

func (o *Options) Logger() log.Logger {
	if o.Log != nil {
		return o.Log
	}
	fields := log.Fields{}
	emptyArch := types.Architecture("")

	if o.Arch != emptyArch {
		fields["arch"] = o.Arch.ToAPK()
	}

	return o.Log.WithFields(fields)
}

// Tempdir returns the temporary directory where apko will create
// the layer blobs
func (o *Options) TempDir() string {
	if o.TempDirPath != "" {
		return o.TempDirPath
	}

	path, err := os.MkdirTemp(os.TempDir(), "apko-temp-*")
	if err != nil {
		o.Logger().Fatalf(fmt.Errorf("creating tempdir: %w", err).Error())
	}
	o.TempDirPath = path
	return o.TempDirPath
}

// TarballFileName returns a deterministic filename for the layer taball
func (o Options) TarballFileName() string {
	tarName := "apko.tar.gz"
	if o.Arch.String() != "" {
		tarName = fmt.Sprintf("apko-%s.tar.gz", o.Arch.ToAPK())
	}
	return tarName
}
