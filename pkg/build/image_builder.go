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

package build

import (
	"fmt"

	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/s6"
)

func (di *buildImplementation) ValidateImageConfiguration(ic *types.ImageConfiguration) error {
	if err := ic.Validate(); err != nil {
		return fmt.Errorf("failed to validate configuration: %w", err)
	}
	return nil
}

func (di *buildImplementation) WriteSupervisionTree(
	s6context *s6.Context, imageConfig *types.ImageConfiguration,
) error {
	// write service supervision tree
	s6m := make(map[interface{}]interface{}, len(imageConfig.Entrypoint.Services))
	for k, v := range imageConfig.Entrypoint.Services {
		s6m[k] = v
	}
	if err := s6context.WriteSupervisionTree(s6m); err != nil {
		return fmt.Errorf("failed to write supervision tree: %w", err)
	}
	return nil
}
