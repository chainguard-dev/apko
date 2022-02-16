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

package cli

import (
	"github.com/spf13/cobra"
	"chainguard.dev/apko/pkg/build"
)

func Build() *cobra.Command {
	cmd := &cobra.Command{
		Use:			"build",
		Short:			"Build an image from a YAML configuration file",
		Long:			"Build an image from a YAML configuration file",
		Example:		`  apko build <config.yaml> <tag> <output.tar.gz>`,
		Args:			cobra.ExactArgs(3),
		RunE:			func(cmd *cobra.Command, args[] string) error {
						return build.BuildCmd(cmd.Context(), args[0], args[1], args[2])
					},
	}

	return cmd
}
