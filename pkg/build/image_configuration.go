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

package build

import (
	"log"
	"os"

	"gopkg.in/yaml.v3"
)

type ImageConfiguration struct {
	Contents struct {
		Repositories []string
		Keyring []string
		Packages []string
	}
	Entrypoint struct {
		Type string
		Command string

		// TBD: presently a map of service names and the command to run
		Services map[interface{}]interface{}
	}
}

func LoadImageConfiguration(imageConfigPath string) (ImageConfiguration, error) {
	ic := ImageConfiguration{}

	data, err := os.ReadFile(imageConfigPath)
	if err != nil {
		log.Fatalf("failed to read file %s: %v", imageConfigPath, err)
	}

	err = yaml.Unmarshal(data, &ic)
	if err != nil {
		log.Fatalf("failed to parse file %s: %v", imageConfigPath, err)
	}

	return ic, nil
}
