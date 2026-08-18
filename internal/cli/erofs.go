// Copyright 2026 Chainguard, Inc.
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
	"os"

	"github.com/spf13/cobra"

	"chainguard.dev/apko/pkg/erofsmount"
)

// erofsCmd returns the `apko erofs` parent command, which hosts the ls
// subcommand.
func erofsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "erofs",
		Short: "Inspect EROFS images produced by apko",
		Long: `The erofs subcommands operate on EROFS layer blobs and OCI image
directories whose layers use the application/vnd.erofs mediaType (as produced
by 'apko build --format=erofs').`,
	}
	cmd.AddCommand(erofsLs())
	return cmd
}

func erofsLs() *cobra.Command {
	var arch string
	cmd := &cobra.Command{
		Use:   "ls SOURCE",
		Short: "List the contents of an EROFS blob or image",
		Long: `Walk the contents of SOURCE and print a 'tar tvf'-style listing:
mode, uid/gid, size (major,minor for devices), mtime, and path.

SOURCE may be:
  - a raw EROFS blob file,
  - an OCI image layout directory containing EROFS layers,
  - any of the above prefixed by erofs:, oci:, or oci-dir:,
  - PATH:TAG to pick a manifest from a multi-tag OCI layout.

SOURCE is read directly with go-erofs and nothing is mounted, so this works
without root and on any platform. Uncompressed images only.`,
		Example: `  apko erofs ls ./image.erofs
  apko erofs ls ./out
  apko erofs ls oci-dir:./out:latest`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			src, err := erofsmount.ParseSource(args[0])
			if err != nil {
				return err
			}
			return erofsmount.Ls(cmd.Context(), src, arch, os.Stdout)
		},
	}
	cmd.Flags().StringVar(&arch, "arch", "host", "architecture to select from a multi-arch OCI index")
	return cmd
}
