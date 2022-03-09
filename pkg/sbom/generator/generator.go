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

package generator

import (
	"chainguard.dev/apko/pkg/sbom/generator/cyclonedx"
	"chainguard.dev/apko/pkg/sbom/options"
)

type Generator interface {
	Key() string
	Ext() string
	Generate(*options.Options, string) error
}

func Generators() map[string]Generator {
	generators := map[string]Generator{}

	cdx := cyclonedx.New()
	generators[cdx.Key()] = &cdx

	return generators
}
