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

// Package erofsmount provides the building blocks for the `apko erofs`
// subcommands (mount, umount, ls). It exposes a small library: parse a source
// spec, read an OCI layout's EROFS layers, drive kernel or FUSE mounts, and
// persist/restore mount state for tear-down.
package erofsmount

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Kind distinguishes a raw EROFS blob from an OCI layout directory.
type Kind int

const (
	// KindBlob is a single raw EROFS filesystem image on disk.
	KindBlob Kind = iota
	// KindOCIDir is an OCI image layout directory whose layer mediaTypes are
	// application/vnd.erofs.
	KindOCIDir
)

func (k Kind) String() string {
	switch k {
	case KindBlob:
		return "blob"
	case KindOCIDir:
		return "oci-dir"
	}
	return "unknown"
}

// Source is a resolved reference to either an EROFS blob or an OCI layout.
type Source struct {
	Kind Kind
	// Path is the absolute, cleaned path on disk.
	Path string
	// Tag, for KindOCIDir, optionally selects a manifest via the
	// org.opencontainers.image.ref.name annotation in index.json. Empty means
	// "use the sole manifest in the index".
	Tag string
	// Raw is the original spec the user passed, preserved for error messages.
	Raw string
}

const (
	prefixErofs  = "erofs:"
	prefixOCI    = "oci:"
	prefixOCIDir = "oci-dir:"
)

// ParseSource resolves a user-supplied source spec into a Source. Accepted
// forms (checked in order):
//
//   - "erofs:PATH"           force KindBlob.
//   - "oci:PATH[:TAG]"       force KindOCIDir.
//   - "oci-dir:PATH[:TAG]"   force KindOCIDir.
//   - "PATH"                 auto-detect: regular file → blob; directory
//     containing an `oci-layout` file → OCI dir.
//   - "PATH:TAG"             only attempted when bare "PATH:TAG" doesn't
//     resolve on disk; splits on the *last* colon and treats LHS as an OCI
//     directory.
func ParseSource(spec string) (Source, error) {
	if spec == "" {
		return Source{}, fmt.Errorf("empty source spec")
	}

	switch {
	case strings.HasPrefix(spec, prefixErofs):
		return resolveBlob(spec, strings.TrimPrefix(spec, prefixErofs))
	case strings.HasPrefix(spec, prefixOCIDir):
		return resolveOCIDir(spec, strings.TrimPrefix(spec, prefixOCIDir))
	case strings.HasPrefix(spec, prefixOCI):
		return resolveOCIDir(spec, strings.TrimPrefix(spec, prefixOCI))
	}

	// No prefix: stat the bare spec first; only fall back to path:tag splitting
	// if it doesn't exist (so a directory containing a colon in its name still
	// works when stat succeeds).
	if info, err := os.Stat(spec); err == nil {
		return classifyExisting(spec, info, spec, "")
	}

	if idx := strings.LastIndex(spec, ":"); idx > 0 {
		path, tag := spec[:idx], spec[idx+1:]
		if tag == "" {
			return Source{}, fmt.Errorf("source %q: empty tag after %q", spec, ":")
		}
		info, err := os.Stat(path)
		if err == nil {
			return classifyExisting(spec, info, path, tag)
		}
	}

	return Source{}, fmt.Errorf("source %q: not found", spec)
}

func resolveBlob(raw, path string) (Source, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Source{}, fmt.Errorf("source %q: %w", raw, err)
	}
	if !info.Mode().IsRegular() {
		return Source{}, fmt.Errorf("source %q: %s is not a regular file (erofs: requires a blob file)", raw, path)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return Source{}, fmt.Errorf("source %q: resolve path: %w", raw, err)
	}
	return Source{Kind: KindBlob, Path: filepath.Clean(abs), Raw: raw}, nil
}

func resolveOCIDir(raw, rest string) (Source, error) {
	path, tag := rest, ""
	if idx := strings.LastIndex(rest, ":"); idx > 0 {
		// Only treat the rightmost colon as a tag separator if the prefix
		// resolves to an OCI directory; otherwise the colon is part of the
		// path (e.g. a directory whose name contains a colon).
		candidatePath := rest[:idx]
		candidateTag := rest[idx+1:]
		if info, err := os.Stat(candidatePath); err == nil && info.IsDir() && hasOCILayout(candidatePath) {
			path, tag = candidatePath, candidateTag
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		return Source{}, fmt.Errorf("source %q: %w", raw, err)
	}
	if !info.IsDir() {
		return Source{}, fmt.Errorf("source %q: %s is not a directory (oci-dir: requires an OCI image layout)", raw, path)
	}
	if !hasOCILayout(path) {
		return Source{}, fmt.Errorf("source %q: %s is not an OCI image layout (no `oci-layout` file)", raw, path)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return Source{}, fmt.Errorf("source %q: resolve path: %w", raw, err)
	}
	return Source{Kind: KindOCIDir, Path: filepath.Clean(abs), Tag: tag, Raw: raw}, nil
}

// classifyExisting routes a bare (no-prefix) spec whose primary path already
// exists on disk. tag is empty when the spec contained no `:tag` portion.
func classifyExisting(raw string, info os.FileInfo, path, tag string) (Source, error) {
	switch {
	case info.Mode().IsRegular():
		if tag != "" {
			return Source{}, fmt.Errorf("source %q: %s is a file; a :tag selector is only meaningful for an OCI layout", raw, path)
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			return Source{}, fmt.Errorf("source %q: resolve path: %w", raw, err)
		}
		return Source{Kind: KindBlob, Path: filepath.Clean(abs), Raw: raw}, nil
	case info.IsDir():
		if !hasOCILayout(path) {
			return Source{}, fmt.Errorf("source %q: %s is a directory but not an OCI image layout (no `oci-layout` file)", raw, path)
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			return Source{}, fmt.Errorf("source %q: resolve path: %w", raw, err)
		}
		return Source{Kind: KindOCIDir, Path: filepath.Clean(abs), Tag: tag, Raw: raw}, nil
	default:
		return Source{}, fmt.Errorf("source %q: %s is not a regular file or directory", raw, path)
	}
}

// hasOCILayout reports whether dir contains the marker file `oci-layout` that
// designates an OCI image layout directory per the image-spec.
func hasOCILayout(dir string) bool {
	info, err := os.Stat(filepath.Join(dir, "oci-layout"))
	return err == nil && info.Mode().IsRegular()
}
