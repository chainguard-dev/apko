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

package types

import (
	"os"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"
)

// Loads an image configuration given a configuration file path.
func (ic *ImageConfiguration) Load(imageConfigPath string) error {
	data, err := os.ReadFile(imageConfigPath)
	if err != nil {
		return errors.Wrap(err, "failed to read image configuration file")
	}

	err = yaml.Unmarshal(data, ic)
	if err != nil {
		return errors.Wrap(err, "failed to parse image configuration")
	}

	return nil
}

// Do preflight checks and mutations on an image configuration.
func (ic *ImageConfiguration) Validate() error {
	if ic.Entrypoint.Type == "service-bundle" {
		return ic.ValidateServiceBundle()
	}

	return nil
}

// Do preflight checks and mutations on an image configured to manage
// a service bundle.
func (ic *ImageConfiguration) ValidateServiceBundle() error {
	ic.Entrypoint.Command = "/bin/s6-svscan /sv"

	// It's harmless to have a duplicate entry in /etc/apk/world,
	// apk will fix it up when the fixate op happens.
	ic.Contents.Packages = append(ic.Contents.Packages, "s6")

	return nil
}
