// Copyright 2023 Chainguard, Inc.
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

package cli_test

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/validate"
	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/internal/cli"
	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/build/types"
)

// showImageDiff - show changes between two images
//
// showImageDiff will show the changes between 2 images including
// changes inside the layers.
//
// It will write to the provided io.Writer `diff`-like output showing the
// differences between imgFrom and imgTo.
//  1. a diff of the image config
//  2. a diff of sorted `tar tvf`-like output for each layer in the image
//     showing numeric uid and gid.
//  3. a recursive diff of the contents of each layer
//     this will only show differences in the file content between
//     files that are present in both the imgFrom layer and imgTo layer
//     the diff of the tvf will indicate added or changed paths.
//     sockets, and devices and symlinks will be skipped.  Changes to
//     these type of files will show up in the tvf diff.
func showImageDiff(out io.Writer, imgFrom, imgTo v1.ImageIndex) {
	// Get the manifest for each index
	fromManifest, err := imgFrom.IndexManifest()
	if err != nil {
		fmt.Fprintf(out, "Error getting from manifest: %v\n", err)
		return
	}
	toManifest, err := imgTo.IndexManifest()
	if err != nil {
		fmt.Fprintf(out, "Error getting to manifest: %v\n", err)
		return
	}

	// Compare index manifests
	fmt.Fprintf(out, "=== Image Index Manifest Diff ===\n")
	fromBytes, _ := json.MarshalIndent(fromManifest, "", "  ")
	toBytes, _ := json.MarshalIndent(toManifest, "", "  ")
	if diff := cmp.Diff(string(fromBytes), string(toBytes)); diff != "" {
		fmt.Fprintf(out, "%s\n", diff)
	} else {
		fmt.Fprintf(out, "Index manifests are identical\n")
	}

	// Process each architecture/platform image
	fromImages := make(map[string]v1.Image)
	toImages := make(map[string]v1.Image)

	// Collect images from both indices
	for _, desc := range fromManifest.Manifests {
		if desc.Platform != nil {
			key := fmt.Sprintf("%s/%s", desc.Platform.OS, desc.Platform.Architecture)
			img, err := imgFrom.Image(desc.Digest)
			if err != nil {
				fmt.Fprintf(out, "Error getting from image %s: %v\n", key, err)
				continue
			}
			fromImages[key] = img
		}
	}

	for _, desc := range toManifest.Manifests {
		if desc.Platform != nil {
			key := fmt.Sprintf("%s/%s", desc.Platform.OS, desc.Platform.Architecture)
			img, err := imgTo.Image(desc.Digest)
			if err != nil {
				fmt.Fprintf(out, "Error getting to image %s: %v\n", key, err)
				continue
			}
			toImages[key] = img
		}
	}

	// Compare images for each platform
	allPlatforms := make(map[string]bool)
	for k := range fromImages {
		allPlatforms[k] = true
	}
	for k := range toImages {
		allPlatforms[k] = true
	}

	for platform := range allPlatforms {
		fmt.Fprintf(out, "\n=== Platform %s ===\n", platform)

		fromImg, hasFrom := fromImages[platform]
		toImg, hasTo := toImages[platform]

		if !hasFrom {
			fmt.Fprintf(out, "Image missing in FROM\n")
			continue
		}
		if !hasTo {
			fmt.Fprintf(out, "Image missing in TO\n")
			continue
		}

		// Compare configs
		compareImageConfigs(out, fromImg, toImg)

		// Compare layers
		compareLayers(out, fromImg, toImg)
	}
}

func compareImageConfigs(out io.Writer, fromImg, toImg v1.Image) {
	fmt.Fprintf(out, "\n--- Image Config Diff ---\n")

	fromConfig, err := fromImg.ConfigFile()
	if err != nil {
		fmt.Fprintf(out, "Error getting from config: %v\n", err)
		return
	}

	toConfig, err := toImg.ConfigFile()
	if err != nil {
		fmt.Fprintf(out, "Error getting to config: %v\n", err)
		return
	}

	fromBytes, _ := json.MarshalIndent(fromConfig, "", "  ")
	toBytes, _ := json.MarshalIndent(toConfig, "", "  ")

	if diff := cmp.Diff(string(fromBytes), string(toBytes)); diff != "" {
		fmt.Fprintf(out, "%s\n", diff)
	} else {
		fmt.Fprintf(out, "Image configs are identical\n")
	}
}

func compareLayers(out io.Writer, fromImg, toImg v1.Image) {
	fmt.Fprintf(out, "\n--- Layer Comparison ---\n")

	fromLayers, err := fromImg.Layers()
	if err != nil {
		fmt.Fprintf(out, "Error getting from layers: %v\n", err)
		return
	}

	toLayers, err := toImg.Layers()
	if err != nil {
		fmt.Fprintf(out, "Error getting to layers: %v\n", err)
		return
	}

	maxLayers := len(fromLayers)
	if len(toLayers) > maxLayers {
		maxLayers = len(toLayers)
	}

	for i := 0; i < maxLayers; i++ {
		fmt.Fprintf(out, "\n--- Layer %d ---\n", i+1)

		var fromLayer, toLayer v1.Layer
		hasFromLayer := i < len(fromLayers)
		hasToLayer := i < len(toLayers)

		if hasFromLayer {
			fromLayer = fromLayers[i]
		}
		if hasToLayer {
			toLayer = toLayers[i]
		}

		if !hasFromLayer {
			fmt.Fprintf(out, "Layer missing in FROM image\n")
			if hasToLayer {
				fmt.Fprintf(out, "TO layer contents:\n")
				showLayerTvf(out, toLayer)
			}
			continue
		}

		if !hasToLayer {
			fmt.Fprintf(out, "Layer missing in TO image\n")
			fmt.Fprintf(out, "FROM layer contents:\n")
			showLayerTvf(out, fromLayer)
			continue
		}

		// Compare layer digests
		fromDigest, _ := fromLayer.Digest()
		toDigest, _ := toLayer.Digest()

		if fromDigest == toDigest {
			fmt.Fprintf(out, "Layers are identical (digest: %s)\n", fromDigest)
			continue
		}

		fmt.Fprintf(out, "Layer digests differ:\n")
		fmt.Fprintf(out, "  FROM: %s\n", fromDigest)
		fmt.Fprintf(out, "    TO: %s\n", toDigest)

		// Show tvf-style diff
		compareLayerContents(out, fromLayer, toLayer)
	}
}

type FileInfo struct {
	Path       string
	Mode       string
	UID, GID   string
	Size       string
	ModTime    string
	LinkTarget string // for symlinks
}

func showLayerTvf(out io.Writer, layer v1.Layer) {
	files := extractLayerFileList(layer)
	for _, file := range files {
		if file.LinkTarget != "" {
			fmt.Fprintf(out, "%s %s %12s %s %s -> %s\n", file.Mode, file.UID+"/"+file.GID, file.Size, file.ModTime, file.Path, file.LinkTarget)
		} else {
			fmt.Fprintf(out, "%s %s %12s %s %s\n", file.Mode, file.UID+"/"+file.GID, file.Size, file.ModTime, file.Path)
		}
	}
}

func extractLayerFileList(layer v1.Layer) []FileInfo {
	var files []FileInfo

	rc, err := layer.Uncompressed()
	if err != nil {
		return files
	}
	defer rc.Close()

	tr := tar.NewReader(rc)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}

		// Format similar to tar tvf output with numeric uid/gid
		mode := formatMode(header.Typeflag, header.Mode)
		uid := fmt.Sprintf("%d", header.Uid)
		gid := fmt.Sprintf("%d", header.Gid)
		size := formatSize(header.Typeflag, header.Size)
		modTime := header.ModTime.Format("2006-01-02 15:04")

		file := FileInfo{
			Path:    header.Name,
			Mode:    mode,
			UID:     uid,
			GID:     gid,
			Size:    size,
			ModTime: modTime,
		}

		if header.Typeflag == tar.TypeSymlink || header.Typeflag == tar.TypeLink {
			file.LinkTarget = header.Linkname
		}

		files = append(files, file)
	}

	// Sort by path
	sort.Slice(files, func(i, j int) bool {
		return files[i].Path < files[j].Path
	})

	return files
}

func formatMode(typeflag byte, mode int64) string {
	var typeChar string
	switch typeflag {
	case tar.TypeReg:
		typeChar = "-"
	case tar.TypeDir:
		typeChar = "d"
	case tar.TypeSymlink:
		typeChar = "l"
	case tar.TypeLink:
		typeChar = "-" // hard links show as regular files
	case tar.TypeChar:
		typeChar = "c"
	case tar.TypeBlock:
		typeChar = "b"
	case tar.TypeFifo:
		typeChar = "p"
	default:
		typeChar = "?"
	}

	perm := fmt.Sprintf("%03o", mode&0777)
	permStr := ""

	// Convert octal permissions to rwx format
	for i, digit := range perm {
		val := int(digit - '0')
		r := "-"
		w := "-"
		x := "-"
		if val&4 != 0 {
			r = "r"
		}
		if val&2 != 0 {
			w = "w"
		}
		if val&1 != 0 {
			x = "x"
		}

		// Handle special bits
		if i == 0 && mode&04000 != 0 { // setuid
			if x == "x" {
				x = "s"
			} else {
				x = "S"
			}
		}
		if i == 1 && mode&02000 != 0 { // setgid
			if x == "x" {
				x = "s"
			} else {
				x = "S"
			}
		}
		if i == 2 && mode&01000 != 0 { // sticky
			if x == "x" {
				x = "t"
			} else {
				x = "T"
			}
		}

		permStr += r + w + x
	}

	return typeChar + permStr
}

func formatSize(typeflag byte, size int64) string {
	if typeflag == tar.TypeDir {
		return "0"
	}
	if typeflag == tar.TypeChar || typeflag == tar.TypeBlock {
		// For device files, size field contains device numbers
		major := (size >> 8) & 0xff
		minor := size & 0xff
		return fmt.Sprintf("%d,%d", major, minor)
	}
	return fmt.Sprintf("%d", size)
}

func compareLayerContents(out io.Writer, fromLayer, toLayer v1.Layer) {
	fromFiles := extractLayerFileList(fromLayer)
	toFiles := extractLayerFileList(toLayer)

	// Create maps for easy lookup
	fromMap := make(map[string]FileInfo)
	toMap := make(map[string]FileInfo)

	for _, f := range fromFiles {
		fromMap[f.Path] = f
	}
	for _, f := range toFiles {
		toMap[f.Path] = f
	}

	// Get all unique paths
	allPaths := make(map[string]bool)
	for path := range fromMap {
		allPaths[path] = true
	}
	for path := range toMap {
		allPaths[path] = true
	}

	// Convert to sorted slice
	paths := make([]string, len(allPaths))
	for path := range allPaths {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	fmt.Fprintf(out, "Layer file listing diff:\n")

	for _, path := range paths {
		fromFile, hasFrom := fromMap[path]
		toFile, hasTo := toMap[path]

		switch {
		case !hasFrom:
			// File added
			if toFile.LinkTarget != "" {
				fmt.Fprintf(out, "+%s %s %12s %s %s -> %s\n", toFile.Mode, toFile.UID+"/"+toFile.GID, toFile.Size, toFile.ModTime, toFile.Path, toFile.LinkTarget)
			} else {
				fmt.Fprintf(out, "+%s %s %12s %s %s\n", toFile.Mode, toFile.UID+"/"+toFile.GID, toFile.Size, toFile.ModTime, toFile.Path)
			}
		case !hasTo:
			// File removed
			if fromFile.LinkTarget != "" {
				fmt.Fprintf(out, "-%s %s %12s %s %s -> %s\n", fromFile.Mode, fromFile.UID+"/"+fromFile.GID, fromFile.Size, fromFile.ModTime, fromFile.Path, fromFile.LinkTarget)
			} else {
				fmt.Fprintf(out, "-%s %s %12s %s %s\n", fromFile.Mode, fromFile.UID+"/"+fromFile.GID, fromFile.Size, fromFile.ModTime, fromFile.Path)
			}
		default:
			// File exists in both, check if different
			if fromFile.Mode != toFile.Mode || fromFile.Size != toFile.Size || fromFile.LinkTarget != toFile.LinkTarget {
				// Show both versions
				if fromFile.LinkTarget != "" {
					fmt.Fprintf(out, "-%s %s %12s %s %s -> %s\n", fromFile.Mode, fromFile.UID+"/"+fromFile.GID, fromFile.Size, fromFile.ModTime, fromFile.Path, fromFile.LinkTarget)
				} else {
					fmt.Fprintf(out, "-%s %s %12s %s %s\n", fromFile.Mode, fromFile.UID+"/"+fromFile.GID, fromFile.Size, fromFile.ModTime, fromFile.Path)
				}
				if toFile.LinkTarget != "" {
					fmt.Fprintf(out, "+%s %s %12s %s %s -> %s\n", toFile.Mode, toFile.UID+"/"+toFile.GID, toFile.Size, toFile.ModTime, toFile.Path, toFile.LinkTarget)
				} else {
					fmt.Fprintf(out, "+%s %s %12s %s %s\n", toFile.Mode, toFile.UID+"/"+toFile.GID, toFile.Size, toFile.ModTime, toFile.Path)
				}
			}
		}
	}

	// Compare file contents for regular files that exist in both layers
	fmt.Fprintf(out, "\nFile content diffs:\n")
	compareFileContents(out, fromLayer, toLayer, fromMap, toMap)
}

func compareFileContents(out io.Writer, fromLayer, toLayer v1.Layer, fromMap, toMap map[string]FileInfo) {
	// Get file contents from both layers
	fromContents := extractLayerFileContents(fromLayer)
	toContents := extractLayerFileContents(toLayer)

	// Compare contents for files that exist in both
	for path := range fromMap {
		if _, exists := toMap[path]; !exists {
			continue
		}

		// Skip non-regular files (directories, symlinks, devices, etc.)
		if !isRegularFile(fromMap[path]) || !isRegularFile(toMap[path]) {
			continue
		}

		fromContent, hasFromContent := fromContents[path]
		toContent, hasToContent := toContents[path]

		if !hasFromContent || !hasToContent {
			continue
		}

		if !bytes.Equal(fromContent, toContent) {
			fmt.Fprintf(out, "File content differs: %s\n", path)
			// Show a simple byte-level diff indication
			fmt.Fprintf(out, "  FROM: %d bytes\n", len(fromContent))
			fmt.Fprintf(out, "  TO:   %d bytes\n", len(toContent))

			// For text files, we could show more detailed diff, but for now just indicate difference
			if len(fromContent) < 1024 && len(toContent) < 1024 && isTextContent(fromContent) && isTextContent(toContent) {
				if diff := cmp.Diff(string(fromContent), string(toContent)); diff != "" {
					fmt.Fprintf(out, "  Text diff:\n%s\n", diff)
				}
			}
		}
	}
}

func isRegularFile(file FileInfo) bool {
	return len(file.Mode) > 0 && file.Mode[0] == '-'
}

func isTextContent(data []byte) bool {
	// Simple heuristic: check if content is mostly printable ASCII
	if len(data) == 0 {
		return true
	}

	viewable := 0
	for _, b := range data {
		if (b >= 32 && b < 127) || b == '\n' || b == '\r' || b == '\t' {
			viewable++
		}
	}

	return float64(viewable)/float64(len(data)) > 0.8
}

func extractLayerFileContents(layer v1.Layer) map[string][]byte {
	contents := make(map[string][]byte)

	rc, err := layer.Uncompressed()
	if err != nil {
		return contents
	}
	defer rc.Close()

	tr := tar.NewReader(rc)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}

		// Only read regular files
		if header.Typeflag == tar.TypeReg {
			data, err := io.ReadAll(tr)
			if err == nil {
				contents[header.Name] = data
			}
		}
	}

	return contents
}

func TestBuild(t *testing.T) {
	ctx := context.Background()
	tmp := t.TempDir()

	golden := filepath.Join("testdata", "golden")
	goldenSboms := filepath.Join(golden, "sboms")
	config := filepath.Join("testdata", "apko.yaml")

	archs := types.ParseArchitectures([]string{"amd64", "arm64"})
	opts := []build.Option{build.WithConfig(config, []string{}), build.WithSBOMFormats([]string{"spdx"}), build.WithTags("golden:latest")}

	sbomPath := filepath.Join(tmp, "sboms")
	err := os.MkdirAll(sbomPath, 0o750)
	require.NoError(t, err)

	err = cli.BuildCmd(ctx, "golden:latest", tmp, archs, []string{}, true, sbomPath, opts...)
	require.NoError(t, err)

	root, err := layout.ImageIndexFromPath(tmp)
	require.NoError(t, err)

	gold, err := layout.ImageIndexFromPath(golden)
	require.NoError(t, err)

	// Not strictly necessary, but this will validate that the index is well-formed.
	require.NoError(t, validate.Index(root))
	require.NoError(t, validate.Index(gold))

	// TODO: We should diff manifests and layer contents.
	got, err := root.Digest()
	require.NoError(t, err)

	want, err := gold.Digest()
	require.NoError(t, err)

	if want != got {
		showImageDiff(os.Stderr, gold, root)
	}
	require.Equal(t, want, got)

	// Check that the sbomPath is not empty.
	sboms, err := os.ReadDir(goldenSboms)
	require.NoError(t, err)
	require.NotEmpty(t, sboms)

	for _, s := range sboms {
		goldSbom := filepath.Join(goldenSboms, s.Name())
		sbom := filepath.Join(sbomPath, s.Name())

		want, err := os.ReadFile(goldSbom)
		require.NoError(t, err)

		got, err := os.ReadFile(sbom)
		require.NoError(t, err)

		if bytes.Equal(want, got) {
			continue
		}

		// https://github.com/google/go-cmp/issues/224#issuecomment-650429859
		transformJSON := cmp.FilterValues(func(x, y []byte) bool {
			return json.Valid(x) && json.Valid(y)
		}, cmp.Transformer("ParseJSON", func(in []byte) (out interface{}) {
			if err := json.Unmarshal(in, &out); err != nil {
				panic(err) // should never occur given previous filter to ensure valid JSON
			}
			return out
		}))

		if diff := cmp.Diff(want, got, transformJSON); diff != "" {
			t.Errorf("Mismatched SBOMs (-%q +%q):\n%s", goldSbom, sbom, diff)
		}
	}
}

func TestBuildWithBase(t *testing.T) {
	// top_image golden file can be regenerated using ./internal/cli/testdata/regenerate_golden_top_image.sh script.

	// TODO(sfc-gh-mhazy) Check sboms after base image support is reflected in them.

	ctx := context.Background()
	tmp := t.TempDir()
	apkoTempDir := t.TempDir()

	golden := filepath.Join("testdata", "top_image")
	config := filepath.Join("testdata", "image_on_top.apko.yaml")
	lockfile := filepath.Join("testdata", "image_on_top.apko.lock.json")

	archs := types.ParseArchitectures([]string{"amd64", "arm64"})
	opts := []build.Option{build.WithConfig(config, []string{}), build.WithSBOMFormats([]string{"spdx"}), build.WithTags("golden_top:latest"), build.WithLockFile(lockfile), build.WithTempDir(apkoTempDir)}

	sbomPath := filepath.Join(tmp, "sboms")
	err := os.MkdirAll(sbomPath, 0o750)
	require.NoError(t, err)

	err = cli.BuildCmd(ctx, "golden_top:latest", tmp, archs, []string{}, true, sbomPath, opts...)
	require.NoError(t, err)

	root, err := layout.ImageIndexFromPath(tmp)
	require.NoError(t, err)

	gold, err := layout.ImageIndexFromPath(golden)
	require.NoError(t, err)

	// Not strictly necessary, but this will validate that the index is well-formed.
	require.NoError(t, validate.Index(root))
	require.NoError(t, validate.Index(gold))

	// TODO: We should diff manifests and layer contents.
	got, err := root.Digest()
	require.NoError(t, err)

	want, err := gold.Digest()
	require.NoError(t, err)

	require.Equal(t, want, got)
}
