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
	"os"
	"time"

	erofs "github.com/erofs/go-erofs"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"go.opentelemetry.io/otel"
	"golang.org/x/sys/unix"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/build/types"
)

// writeErofs serializes fsys as a raw (uncompressed) EROFS filesystem image to
// out. out must be both writable and seekable: go-erofs's Writer rewrites the
// superblock at offset 0 after streaming file data.
//
// buildTime sets the EROFS image build time, which seeds per-entry mtime
// defaulting and is recorded in the superblock. It is always passed through, so
// the image is reproducible for any caller; see erofsBuildTime.
func writeErofs(ctx context.Context, out io.WriteSeeker, fsys apkfs.FullFS, buildTime time.Time) error {
	ctx, span := otel.Tracer("apko").Start(ctx, "writeErofs")
	defer span.End()

	sec, nsec := erofsBuildTime(buildTime)
	w := erofs.Create(out, erofs.WithBuildTime(sec, nsec))

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

// erofsBuildTime converts a build timestamp into the seconds/nanoseconds pair
// erofs.WithBuildTime takes.
//
// The option is always passed, never omitted: go-erofs v0.3.1 stamps
// time.Now().Unix() into the superblock from Writer.Close when it is absent, so
// a caller who leaves the timestamp zero would get a different digest on every
// build -- exactly where they would least expect it. apko's own CLI is covered
// because options.Default sets SourceDateEpoch to time.Unix(0, 0), but library
// callers construct their own.
//
// A zero time.Time has a large negative Unix seconds value, which would wrap
// when converted to uint64, so a zero or pre-epoch timestamp is clamped to
// epoch 0. That is what an unset SOURCE_DATE_EPOCH already means to apko, and
// it is at least reproducible.
func erofsBuildTime(t time.Time) (sec uint64, nsec uint32) {
	if t.Unix() < 0 {
		return 0, 0
	}
	return uint64(t.Unix()), uint32(t.Nanosecond())
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
		// Hardlinks are materialized as independent copies. apko's FullFS
		// surfaces a hardlink as an ordinary second dirent -- its linkness
		// shows up only in the *tar.Header from Sys() (TypeLink/Linkname),
		// which the tar layer path uses via tar.FileInfoHeader -- and go-erofs
		// v0.3.1 has no API to point two names at one NID. (SetNlink sets the
		// reported link count but does not share the inode, so it would only
		// make the metadata lie.) Every link therefore costs another full copy
		// of the data, rounded up to the block size, and st_nlink/st_ino
		// identity is lost. Spec §3.7's materialize-or-fail rule governs
		// cross-layer links; for links within one layer the spec says nothing,
		// so materializing is conformant but not something §3.7 blesses.
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
	default:
		return fmt.Errorf("unsupported file mode for %s: %v", absPath, mode)
	}

	// Mkdir, Mknod and Create all take only the permission bits, so
	// setuid/setgid/sticky have to be applied on top — losing them would
	// silently break su/passwd/mount and unprotect /tmp. Symlinks are
	// exempt: EROFS pins them at 0777 and chmod on one is meaningless.
	//
	// This is a workaround for a bug in the pinned go-erofs, not a permanent
	// shape. erofs/go-erofs#41 fixed both halves of it -- Mkdir dropping the
	// special bits on write, and FileInfo.Mode() misreporting them on read --
	// but it merged 2026-08-02, after v0.3.1 was tagged 2026-07-21, so the
	// pinned version has neither half.
	//
	// The read half matters even though this Chmod covers the write half:
	// FileInfo.Mode() from the pinned reader cannot be trusted for
	// setuid/setgid/sticky. Code that needs a mode must read *erofs.Stat.Mode
	// off Sys() instead, which is what pkg/erofsmount/ls.go does. Revisit both
	// once a release containing #41 is out.
	if mode&fs.ModeSymlink == 0 {
		if err := w.Chmod(absPath, mode); err != nil {
			return fmt.Errorf("chmod %s: %w", absPath, err)
		}
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
		// apko's FullFS implementations keep xattrs in memory for every node
		// they know about, so an error here means the path we just walked has
		// gone missing — a bug worth surfacing, not something to skip past.
		xattrs, err := fsys.ListXattrs(fsysPath)
		if err != nil {
			return fmt.Errorf("list xattrs %s: %w", fsysPath, err)
		}
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

// buildErofsLayerFromFile takes a finalized EROFS image already serialized to
// path and returns a v1.Layer wrapping it. For the raw `application/vnd.erofs`
// media type the DiffID and Digest are identical: the SHA-256 of the on-wire
// blob bytes (per spec §5.2). annotations, when non-empty, are surfaced on the
// layer's descriptor via the LayerAnnotations() accessor.
func buildErofsLayerFromFile(path string, annotations map[string]string) (v1.Layer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		return nil, fmt.Errorf("hashing erofs layer %s: %w", path, err)
	}

	hash := v1.Hash{
		Algorithm: "sha256",
		Hex:       hex.EncodeToString(h.Sum(make([]byte, 0, h.Size()))),
	}

	return &erofsLayer{
		path:        path,
		hash:        hash,
		size:        size,
		annotations: annotations,
	}, nil
}

// erofsLayer implements v1.Layer for raw, uncompressed EROFS blobs. Digest and
// DiffID are equal; Compressed and Uncompressed return the same bytes.
type erofsLayer struct {
	path        string
	hash        v1.Hash
	size        int64
	annotations map[string]string
}

// LayerAnnotations returns annotations to apply to this layer's manifest
// descriptor. apko/oci consults this via an opt-in interface assertion.
func (l *erofsLayer) LayerAnnotations() map[string]string { return l.annotations }

func (l *erofsLayer) DiffID() (v1.Hash, error) { return l.hash, nil }
func (l *erofsLayer) Digest() (v1.Hash, error) { return l.hash, nil }
func (l *erofsLayer) Size() (int64, error)     { return l.size, nil }
func (l *erofsLayer) MediaType() (v1types.MediaType, error) {
	return v1types.MediaType(types.ErofsLayerMediaType), nil
}

func (l *erofsLayer) Uncompressed() (io.ReadCloser, error) { return os.Open(l.path) }
func (l *erofsLayer) Compressed() (io.ReadCloser, error)   { return os.Open(l.path) }
