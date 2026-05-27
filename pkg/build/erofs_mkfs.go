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

package build

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/chainguard-dev/clog"
	v1 "github.com/google/go-containerregistry/pkg/v1"

	"chainguard.dev/apko/pkg/apk/apk"
	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/build/types"
)

// mkfsZeroUUID is the all-zero UUID used for reproducible builds. mkfs.erofs
// would otherwise generate a fresh UUID for every invocation.
const mkfsZeroUUID = "00000000-0000-0000-0000-000000000000"

// preflightMkfsErofs verifies that mkfs.erofs is on PATH before any caller
// invokes it. The error message points at the format string the user passed
// so the cause is obvious.
func preflightMkfsErofs(ctx context.Context, format types.LayerFormat) error {
	if _, err := exec.LookPath("mkfs.erofs"); err != nil {
		return fmt.Errorf("--format=%s requires mkfs.erofs in PATH (install erofs-utils): %w", format, err)
	}
	clog.FromContext(ctx).Infof("EROFS writer: using mkfs.erofs for format %q", format)
	return nil
}

// buildMkfsCompressionArg renders the -z value mkfs.erofs expects from the
// parsed compressor name and (optional) level. compressor must be non-empty.
func buildMkfsCompressionArg(compressor string, level int) string {
	if level > 0 {
		return fmt.Sprintf("-z%s,level=%d", compressor, level)
	}
	return "-z" + compressor
}

// runMkfsErofs runs mkfs.erofs to convert the uncompressed tar bytes at
// tarPath into an EROFS image at outPath. buildTime is used as the
// reproducible build timestamp (-T); per-file mtimes from the tar are
// preserved. compressor selects the -z algorithm; pass "" for an
// uncompressed image (though the typical mkfs.erofs path is the compressed
// case — uncompressed builds use go-erofs).
func runMkfsErofs(ctx context.Context, outPath, tarPath string, buildTime time.Time, compressor string, level int) error {
	log := clog.FromContext(ctx)

	args := []string{
		"-U", mkfsZeroUUID,
		"--mkfs-time",                                 // -T is build time only; per-file mtimes from tar.
		"-T", strconv.FormatInt(buildTime.Unix(), 10), //nolint:gosec
		"--tar=f",
	}
	if compressor != "" {
		args = append([]string{buildMkfsCompressionArg(compressor, level)}, args...)
	}
	args = append(args, outPath, tarPath)

	// Reproducibility: also pin the umask and any locale-sensitive bits that
	// mkfs.erofs may consult. (mkfs.erofs reads the source paths bytewise so
	// locale shouldn't matter, but force a known LC_ALL just in case.)
	cmd := exec.CommandContext(ctx, "mkfs.erofs", args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	log.Debugf("exec: mkfs.erofs %s", strings.Join(args, " "))
	if err := cmd.Run(); err != nil {
		trimmed := strings.TrimSpace(stderr.String())
		if trimmed != "" {
			return fmt.Errorf("mkfs.erofs %s: %w: %s", strings.Join(args, " "), err, trimmed)
		}
		return fmt.Errorf("mkfs.erofs %s: %w", strings.Join(args, " "), err)
	}
	return nil
}

// writeERofsViaMkfs is the mkfs.erofs equivalent of writeERofs for the
// single-layer build path. It serializes fsys to a temp tar file, runs
// mkfs.erofs to produce outPath, and removes the temp tar on return.
func writeERofsViaMkfs(ctx context.Context, outPath string, fsys apkfs.FullFS, buildTime time.Time, compressor string, level int) error {
	tarFile, err := os.CreateTemp(filepath.Dir(outPath), "apko-erofs-mkfs-*.tar")
	if err != nil {
		return fmt.Errorf("creating tar tempfile: %w", err)
	}
	tarPath := tarFile.Name()
	defer os.Remove(tarPath)

	tw := tar.NewWriter(tarFile)
	if err := writeTar(ctx, tw, fsys); err != nil {
		_ = tarFile.Close()
		return fmt.Errorf("writing tar input for mkfs.erofs: %w", err)
	}
	if err := tw.Close(); err != nil {
		_ = tarFile.Close()
		return fmt.Errorf("closing tar input for mkfs.erofs: %w", err)
	}
	if err := tarFile.Close(); err != nil {
		return fmt.Errorf("closing tar tempfile: %w", err)
	}

	return runMkfsErofs(ctx, outPath, tarPath, buildTime, compressor, level)
}

// splitErofsLayersViaMkfs is the mkfs.erofs equivalent of splitErofsLayers.
// It reuses the existing tar-based grouping logic from splitLayers to
// produce one uncompressed-tar layer per group, then runs mkfs.erofs on
// each to convert to a compressed EROFS blob. The resulting layers carry
// the same overlay-lower role annotations as the go-erofs path.
func splitErofsLayersViaMkfs(ctx context.Context, fsys apkfs.FullFS, groups []*group, pkgToDiff map[*apk.Package][]byte, tmpdir string, buildTime time.Time, compressor string, level int) ([]v1.Layer, error) {
	tarLayers, err := splitLayers(ctx, fsys, groups, pkgToDiff, tmpdir)
	if err != nil {
		return nil, fmt.Errorf("splitting tar layers for mkfs.erofs: %w", err)
	}

	out := make([]v1.Layer, 0, len(tarLayers))
	for i, tl := range tarLayers {
		layerPath := filepath.Join(tmpdir, fmt.Sprintf("apko-erofs-mkfs-layer-%02d.bin", i))
		if err := convertTarLayerViaMkfs(ctx, tl, layerPath, buildTime, compressor, level); err != nil {
			return nil, fmt.Errorf("converting layer %d: %w", i, err)
		}
		var anns map[string]string
		if i < len(tarLayers)-1 {
			anns = map[string]string{erofsRoleAnnotation: erofsRoleOverlay}
		}
		l, err := buildErofsLayerFromFile(layerPath, anns)
		if err != nil {
			return nil, fmt.Errorf("finalizing layer %d: %w", i, err)
		}
		out = append(out, l)
	}
	return out, nil
}

// convertTarLayerViaMkfs writes the uncompressed tar bytes from tl into a
// temp file and runs mkfs.erofs to produce outPath.
func convertTarLayerViaMkfs(ctx context.Context, tl v1.Layer, outPath string, buildTime time.Time, compressor string, level int) (retErr error) {
	tarFile, err := os.CreateTemp(filepath.Dir(outPath), "apko-erofs-mkfs-*.tar")
	if err != nil {
		return fmt.Errorf("creating tar tempfile: %w", err)
	}
	tarPath := tarFile.Name()
	defer os.Remove(tarPath)

	rc, err := tl.Uncompressed()
	if err != nil {
		_ = tarFile.Close()
		return fmt.Errorf("reading uncompressed tar: %w", err)
	}
	if _, err := io.Copy(tarFile, rc); err != nil {
		_ = rc.Close()
		_ = tarFile.Close()
		return fmt.Errorf("copying tar stream: %w", err)
	}
	if err := errors.Join(rc.Close(), tarFile.Close()); err != nil {
		return fmt.Errorf("closing tar tempfile: %w", err)
	}

	return runMkfsErofs(ctx, outPath, tarPath, buildTime, compressor, level)
}
