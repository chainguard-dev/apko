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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"time"

	erofs "github.com/erofs/go-erofs"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"go.opentelemetry.io/otel"
	"golang.org/x/sys/unix"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
)

// Media types from the draft erofs/erofs-image-spec (PR #1).
// These tracking constants are intentionally kept in one place so they can be
// updated in lockstep with the spec.
const (
	erofsLayerMediaType               = "application/vnd.erofs"
	erofsRoleAnnotation               = "org.erofs.role"
	erofsRoleOverlay                  = "overlay-lower"
	erofsUncompressedDigestAnnotation = "org.erofs.uncompressed-digest"
)

// writeErofs serializes fsys as a raw (uncompressed) EROFS filesystem image to
// out. out must be both writable and seekable: go-erofs's Writer rewrites the
// superblock at offset 0 after streaming file data.
//
// If buildTime is non-zero it sets the EROFS image build time (used to seed
// per-entry mtime defaulting and recorded in the superblock), making the image
// reproducible.
func writeErofs(ctx context.Context, out io.WriteSeeker, fsys apkfs.FullFS, buildTime time.Time) error {
	ctx, span := otel.Tracer("apko").Start(ctx, "writeErofs")
	defer span.End()

	var createOpts []erofs.CreateOpt
	if !buildTime.IsZero() {
		createOpts = append(createOpts, erofs.WithBuildTime(uint64(buildTime.Unix()), uint32(buildTime.Nanosecond())))
	}
	w := erofs.Create(out, createOpts...)

	buf := make([]byte, 1<<20)

	if err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("stat %s: %w", path, err)
		}
		return emitErofsEntry(w, erofsAbsPath(path), path, info, fsys, buf)
	}); err != nil {
		return err
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("finalizing erofs image: %w", err)
	}
	return nil
}

// erofsAbsPath maps an fs.WalkDir-style path (rooted at ".") to the
// absolute path the EROFS writer expects ("/").
func erofsAbsPath(path string) string {
	if path == "." {
		return "/"
	}
	return "/" + path
}

// emitErofsEntry creates one filesystem object in w. absPath is the writer
// path ("/foo/bar"), fsysPath is the source path ("foo/bar") used to look up
// secondary metadata (symlink target, devnode, xattrs, file data). buf is a
// reusable copy buffer for regular file data.
func emitErofsEntry(w *erofs.Writer, absPath, fsysPath string, info fs.FileInfo, fsys apkfs.FullFS, buf []byte) error {
	mode := info.Mode()

	switch {
	case mode&fs.ModeSymlink != 0:
		target, err := fsys.Readlink(fsysPath)
		if err != nil {
			return fmt.Errorf("readlink %s: %w", fsysPath, err)
		}
		if err := w.Symlink(target, absPath); err != nil {
			return fmt.Errorf("symlink %s -> %s: %w", absPath, target, err)
		}
	case mode.IsDir():
		// The root directory ("/") already exists; just sync its metadata.
		if absPath != "/" {
			if err := w.Mkdir(absPath, mode.Perm()); err != nil {
				return fmt.Errorf("mkdir %s: %w", absPath, err)
			}
		} else if err := w.Chmod(absPath, mode.Perm()); err != nil {
			return fmt.Errorf("chmod %s: %w", absPath, err)
		}
	case mode&fs.ModeDevice != 0, mode&fs.ModeCharDevice != 0, mode&fs.ModeNamedPipe != 0, mode&fs.ModeSocket != 0:
		var typeBits uint16
		switch {
		case mode&fs.ModeCharDevice != 0:
			typeBits = unix.S_IFCHR
		case mode&fs.ModeDevice != 0:
			typeBits = unix.S_IFBLK
		case mode&fs.ModeNamedPipe != 0:
			typeBits = unix.S_IFIFO
		case mode&fs.ModeSocket != 0:
			typeBits = unix.S_IFSOCK
		}
		var rdev uint32
		if mode&(fs.ModeDevice|fs.ModeCharDevice) != 0 {
			dev, err := fsys.Readnod(fsysPath)
			if err != nil {
				return fmt.Errorf("readnod %s: %w", fsysPath, err)
			}
			rdev = uint32(dev)
		}
		if err := w.Mknod(absPath, typeBits|uint16(mode.Perm()), rdev); err != nil {
			return fmt.Errorf("mknod %s: %w", absPath, err)
		}
	case mode.IsRegular():
		fout, err := w.Create(absPath)
		if err != nil {
			return fmt.Errorf("create %s: %w", absPath, err)
		}
		if info.Size() > 0 {
			src, err := fsys.Open(fsysPath)
			if err != nil {
				_ = fout.Close()
				return fmt.Errorf("open %s: %w", fsysPath, err)
			}
			_, copyErr := io.CopyBuffer(fout, src, buf)
			closeErr := src.Close()
			if copyErr != nil {
				_ = fout.Close()
				return fmt.Errorf("copy %s: %w", fsysPath, copyErr)
			}
			if closeErr != nil {
				_ = fout.Close()
				return fmt.Errorf("close source %s: %w", fsysPath, closeErr)
			}
		}
		if err := fout.Close(); err != nil {
			return fmt.Errorf("close %s: %w", absPath, err)
		}
		if err := w.Chmod(absPath, mode.Perm()); err != nil {
			return fmt.Errorf("chmod %s: %w", absPath, err)
		}
	default:
		return fmt.Errorf("unsupported file mode for %s: %v", absPath, mode)
	}

	uid, gid := uidGidFromInfo(info)
	if err := w.Chown(absPath, uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", absPath, err)
	}

	if mt := info.ModTime(); !mt.IsZero() {
		if err := w.Chtimes(absPath, time.Time{}, mt); err != nil {
			return fmt.Errorf("chtimes %s: %w", absPath, err)
		}
	}

	if mode.IsRegular() || mode.IsDir() {
		xattrs, _ := fsys.ListXattrs(fsysPath)
		for name, value := range xattrs {
			if err := w.Setxattr(absPath, name, string(value)); err != nil {
				return fmt.Errorf("setxattr %s %s: %w", absPath, name, err)
			}
		}
	}

	return nil
}

// uidGidFromInfo extracts numeric uid/gid from a FileInfo. apko's apkfs
// implementations all stash these in a *tar.Header returned by Sys(); any
// other shape (or nil) falls back to root.
func uidGidFromInfo(info fs.FileInfo) (int, int) {
	if h, ok := info.Sys().(*tar.Header); ok {
		return h.Uid, h.Gid
	}
	return 0, 0
}

// newErofsLayerFile creates a temp file backing a single EROFS layer. The
// caller is responsible for closing and removing it. Permissions are 0600 to
// keep intermediate build artifacts off other users' eyes.
func newErofsLayerFile(tmpdir, pattern string) (*os.File, error) {
	if pattern == "" {
		pattern = "apko-erofs-*.bin"
	}
	f, err := os.CreateTemp(tmpdir, pattern)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return nil, err
	}
	return f, nil
}

// buildErofsLayerFromFile takes a finalized raw (uncompressed) EROFS image at
// path and returns a v1.Layer wrapping it. For raw EROFS, DiffID and Digest
// are identical: the SHA-256 of the on-wire blob bytes (per spec §5.2).
// annotations, when non-empty, are surfaced on the layer's descriptor via the
// LayerAnnotations() accessor.
func buildErofsLayerFromFile(path string, annotations map[string]string) (v1.Layer, error) {
	hash, size, err := hashFile(path)
	if err != nil {
		return nil, fmt.Errorf("hashing erofs layer %s: %w", path, err)
	}
	return &erofsLayer{
		path:        path,
		hash:        hash,
		diffID:      hash,
		size:        size,
		annotations: annotations,
	}, nil
}

// buildCompressedErofsLayerFromFiles wraps a compressed EROFS image at path
// alongside its equivalent uncompressed image at uncompressedPath (the file
// mkfs.erofs would have produced without -z, byte-identical except for the
// internal compression). The compressed file's SHA-256 is Digest; the
// uncompressed file's SHA-256 is DiffID and is also exposed as the
// "org.erofs.uncompressed-digest" descriptor annotation per the draft
// erofs/erofs-image-spec. extra entries are merged on top.
func buildCompressedErofsLayerFromFiles(path, uncompressedPath string, extra map[string]string) (v1.Layer, error) {
	digest, size, err := hashFile(path)
	if err != nil {
		return nil, fmt.Errorf("hashing erofs layer %s: %w", path, err)
	}
	diffID, _, err := hashFile(uncompressedPath)
	if err != nil {
		return nil, fmt.Errorf("hashing uncompressed-equivalent %s: %w", uncompressedPath, err)
	}
	annotations := map[string]string{erofsUncompressedDigestAnnotation: diffID.String()}
	maps.Copy(annotations, extra)
	return &erofsLayer{
		path:             path,
		uncompressedPath: uncompressedPath,
		hash:             digest,
		diffID:           diffID,
		size:             size,
		annotations:      annotations,
	}, nil
}

// hashFile returns the SHA-256 of path's contents and the byte count.
func hashFile(path string) (v1.Hash, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return v1.Hash{}, 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return v1.Hash{}, 0, err
	}
	return v1.Hash{Algorithm: "sha256", Hex: hex.EncodeToString(h.Sum(nil))}, n, nil
}

// erofsLayer implements v1.Layer for EROFS blobs. For raw images path is the
// uncompressed bytes and uncompressedPath is empty, so Compressed() and
// Uncompressed() both read path and hash == diffID. For compressed images
// path holds the compressed wire bytes and uncompressedPath holds the
// equivalent uncompressed image used to serve Uncompressed() and to compute
// DiffID (per spec §5.2 and the org.erofs.uncompressed-digest annotation).
type erofsLayer struct {
	path             string
	uncompressedPath string
	hash             v1.Hash
	diffID           v1.Hash
	size             int64
	annotations      map[string]string
}

// LayerPath returns the on-disk path of this layer's payload. Used by callers
// that need to copy the file (e.g. into an OCI layout).
func (l *erofsLayer) LayerPath() string { return l.path }

// LayerAnnotations returns annotations to apply to this layer's manifest
// descriptor. apko/oci consults this via an opt-in interface assertion.
func (l *erofsLayer) LayerAnnotations() map[string]string { return l.annotations }

func (l *erofsLayer) DiffID() (v1.Hash, error) { return l.diffID, nil }
func (l *erofsLayer) Digest() (v1.Hash, error) { return l.hash, nil }
func (l *erofsLayer) Size() (int64, error)     { return l.size, nil }
func (l *erofsLayer) MediaType() (v1types.MediaType, error) {
	return v1types.MediaType(erofsLayerMediaType), nil
}

func (l *erofsLayer) Compressed() (io.ReadCloser, error) { return os.Open(l.path) }
func (l *erofsLayer) Uncompressed() (io.ReadCloser, error) {
	if l.uncompressedPath != "" {
		return os.Open(l.uncompressedPath)
	}
	return os.Open(l.path)
}
