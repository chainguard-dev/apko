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

package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"runtime"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/spf13/cobra"
	"github.com/u-root/u-root/pkg/cpio"

	"github.com/chainguard-dev/clog"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/build/types"
)

func buildCPIO() *cobra.Command {
	var buildDate string
	var buildArch string
	var sbomPath string

	cmd := &cobra.Command{
		Use:     "build-cpio",
		Short:   "Build a cpio file from a YAML configuration file",
		Long:    "Build a cpio file from a YAML configuration file",
		Example: `  apko build-cpio <config.yaml> <output.cpio.gz>`,
		Hidden:  true,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return BuildCPIOCmd(cmd.Context(), args[1],
				build.WithConfig(args[0], []string{}),
				build.WithBuildDate(buildDate),
				build.WithSBOM(sbomPath),
				build.WithArch(types.ParseArchitecture(buildArch)),
			)
		},
	}

	cmd.Flags().StringVar(&buildDate, "build-date", "", "date used for the timestamps of the files inside the image")
	cmd.Flags().StringVar(&buildArch, "build-arch", runtime.GOARCH, "architecture to build for -- default is Go runtime architecture")
	cmd.Flags().StringVar(&sbomPath, "sbom-path", "", "generate an SBOM")

	return cmd
}

func BuildCPIOCmd(ctx context.Context, cpio string, opts ...build.Option) error {
	log := clog.FromContext(ctx)
	wd, err := os.MkdirTemp("", "apko-*")
	if err != nil {
		return fmt.Errorf("failed to create working directory: %w", err)
	}
	defer os.RemoveAll(wd)

	fs := apkfs.DirFS(wd, apkfs.WithCreateDir())
	bc, err := build.New(ctx, fs, opts...)
	if err != nil {
		return err
	}

	ic := bc.ImageConfiguration()

	if len(ic.Archs) != 0 {
		log.Warnf("ignoring archs in config, only building for current arch (%s)", bc.Arch())
	}

	_, layer, err := bc.BuildLayer(ctx)
	if err != nil {
		return fmt.Errorf("failed to build layer image: %w", err)
	}
	log.Debugf("converting layer to cpio %s", cpio)

	return LayerToCPIO(layer, cpio)
}

func LayerToCPIO(layer v1.Layer, cpioFile string) error {
	// Open the filesystem layer to walk through the file.
	u, err := layer.Uncompressed()
	if err != nil {
		return err
	}
	defer u.Close()
	tarReader := tar.NewReader(u)

	// Create the CPIO file, and set up a deduplicating writer
	// to produce the gzip-compressed CPIO archive.
	f, err := os.Create(cpioFile)
	if err != nil {
		return err
	}
	defer f.Close()
	gzipWriter := gzip.NewWriter(f)
	defer gzipWriter.Close()
	w := cpio.NewDedupWriter(cpio.Newc.Writer(gzipWriter))

	// Iterate through the tar archive entries
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			fmt.Println("Error reading tar entry:", err)
			return err
		}

		// Determine CPIO file mode based on TAR typeflag
		switch header.Typeflag {
		case tar.TypeDir:
			if err := cpio.WriteRecordsAndDirs(w, []cpio.Record{
				cpio.Directory(header.Name, uint64(header.Mode)),
			}); err != nil {
				return err
			}

		case tar.TypeSymlink:
			if err := cpio.WriteRecordsAndDirs(w, []cpio.Record{
				cpio.Symlink(header.Name, header.Linkname),
			}); err != nil {
				return err
			}

		case tar.TypeReg:
			var original bytes.Buffer
			// TODO(mattmoor): Do something better here, but unfortunately the
			// cpio stuff wants a seekable reader, so coming from a tar reader
			// I'm not sure how much leeway we have to do something better
			// than buffering.
			//nolint:gosec
			if _, err := io.Copy(&original, tarReader); err != nil {
				fmt.Println("Error reading file content:", err)
				return err
			}

			if err := cpio.WriteRecordsAndDirs(w, []cpio.Record{
				cpio.StaticFile(header.Name, original.String(), uint64(header.Mode)),
			}); err != nil {
				return err
			}

		case tar.TypeChar:
			if err := cpio.WriteRecordsAndDirs(w, []cpio.Record{
				cpio.CharDev(header.Name, uint64(header.Mode), uint64(header.Devmajor), uint64(header.Devminor)),
			}); err != nil {
				return err
			}

		default:
			fmt.Printf("Unsupported TAR typeflag: %c for %s\n", header.Typeflag, header.Name)
			continue // Skip unsupported types
		}
	}

	return w.WriteRecord(cpio.TrailerRecord)
}
