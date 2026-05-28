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

// erofsCmd returns the `apko erofs` parent command, which hosts mount, umount,
// and ls subcommands.
func erofsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "erofs",
		Short: "Mount, unmount, and inspect EROFS images produced by apko",
		Long: `The erofs subcommands operate on EROFS layer blobs and OCI image
directories whose layers use the application/vnd.erofs mediaType (as produced
by 'apko build --format=erofs'). These commands are Linux-only.`,
	}
	cmd.AddCommand(erofsMount(), erofsUmount(), erofsLs())
	return cmd
}

func erofsMount() *cobra.Command {
	var mode, arch string
	var readOnly bool
	cmd := &cobra.Command{
		Use:   "mount [flags] SOURCE DEST",
		Short: "Mount an EROFS blob or an EROFS OCI image at DEST",
		Long: `Mount the given SOURCE at DEST.

SOURCE may be:
  - a raw EROFS blob file (mounted directly at DEST),
  - an OCI image layout directory containing EROFS layers (mounted as a
    multi-layer overlay rooted at DEST/merged),
  - any of the above prefixed by erofs:, oci:, or oci-dir:,
  - PATH:TAG to pick a manifest from a multi-tag OCI layout.

For OCI sources, DEST gets this layout:
  DEST/layers/00..NN  one per EROFS layer (00 is base)
  DEST/upper          overlayfs upperdir (writable mounts only)
  DEST/work           overlayfs workdir (writable mounts only)
  DEST/merged         the combined view
  DEST/.apko-erofs-mount.json  state for 'apko erofs umount'

With --read-only on a single-layer image, overlayfs is skipped and the
sole layer is mounted directly at DEST/merged.`,
		Example: `  apko erofs mount ./out:latest /mnt/x
  apko erofs mount --mode=fuse ./image.erofs /mnt/y
  apko erofs mount --read-only oci-dir:./out:latest /mnt/z`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			src, err := erofsmount.ParseSource(args[0])
			if err != nil {
				return err
			}
			_, err = erofsmount.Mount(cmd.Context(), src, args[1], erofsmount.Options{
				Mode:     erofsmount.Mode(mode),
				Arch:     arch,
				ReadOnly: readOnly,
			})
			return err
		},
	}
	cmd.Flags().StringVar(&mode, "mode", string(erofsmount.ModeAuto), "mount mode: kernel, fuse, or auto (auto = kernel if root else fuse)")
	cmd.Flags().StringVar(&arch, "arch", "host", "architecture to select from a multi-arch OCI index (host = process arch)")
	cmd.Flags().BoolVar(&readOnly, "read-only", false, "mount the image read-only (omits upperdir/workdir; single-layer images skip overlayfs entirely)")
	return cmd
}

func erofsUmount() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "umount DEST",
		Short: "Unmount an EROFS mount produced by 'apko erofs mount'",
		Long: `Unmount the mount at DEST.

If DEST contains a state file (DEST/.apko-erofs-mount.json) it is treated as
an image mount and every layer plus the overlay is torn down in reverse
order. If DEST has no state file, it is treated as a single blob mount and a
plain umount is attempted (with a fall-back to fusermount).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return erofsmount.Unmount(cmd.Context(), args[0])
		},
	}
	return cmd
}

func erofsLs() *cobra.Command {
	var mode, arch string
	cmd := &cobra.Command{
		Use:   "ls SOURCE",
		Short: "List the contents of an EROFS blob or image",
		Long: `Mount SOURCE read-only to a temporary directory, walk its
contents, and print a 'tar tvf'-style listing. Unmounts automatically when
finished.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			src, err := erofsmount.ParseSource(args[0])
			if err != nil {
				return err
			}
			return erofsmount.Ls(cmd.Context(), src, erofsmount.Options{
				Mode: erofsmount.Mode(mode),
				Arch: arch,
			}, os.Stdout)
		},
	}
	cmd.Flags().StringVar(&mode, "mode", string(erofsmount.ModeAuto), "mount mode: kernel, fuse, or auto")
	cmd.Flags().StringVar(&arch, "arch", "host", "architecture to select from a multi-arch OCI index")
	return cmd
}
