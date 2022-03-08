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

package sbom

const ()

type Options struct {
	OsName    string
	OsID      string
	OsVersion string

	// Working directory,inherited from buid context
	WorkDir string
}

var Default = Options{
	OsName:    "Alpine Linux",
	OsID:      "alpine",
	OsVersion: "Unknown",
}

type SBOM struct {
	impl    sbomImplementation
	Options Options
}

func New() *SBOM {
	return &SBOM{
		impl: &defaultSBOMImplementation{},
	}
}

type sbomImplementation interface {
}

type defaultSBOMImplementation struct{}
