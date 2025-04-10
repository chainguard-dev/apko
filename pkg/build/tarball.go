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
	"archive/tar"
	"context" //nolint:gosec
	"fmt"
	"io"
	"io/fs"
	"iter"
	"os"

	"go.opentelemetry.io/otel"
	"golang.org/x/sys/unix"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/passwd"
)

const xattrTarPAXRecordsPrefix = "SCHILY.xattr."

// writeTar writes a tarball to the provided io.Writer from the provided fs.FS.
// The etc/passwd and etc/group file provide username and group name mappings for the tar.
func writeTar(ctx context.Context, dst io.Writer, fsys apkfs.FullFS) error { //nolint:gocyclo
	ctx, span := otel.Tracer("go-apk").Start(ctx, "writeTar")
	defer span.End()

	tw := tar.NewWriter(dst)
	buf := make([]byte, 1<<20)

	for f, err := range walkFS(ctx, fsys) {
		if err != nil {
			return err
		}
		if err := tw.WriteHeader(f.header); err != nil {
			return err
		}

		if f.info.Mode().IsRegular() && f.header.Size > 0 {
			data, err := fsys.Open(f.path)
			if err != nil {
				return err
			}
			defer data.Close()

			if _, err := io.CopyBuffer(tw, data, buf); err != nil {
				return err
			}
		}
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("closing tar writer: %w", err)
	}
	return nil
}

// file holds all the info we need to yield from walkFS.
//
// We need both Header and info because the fs.DirEntry.Info()
// implementation is controlled by our tarfs implementation,
// and we use that as a sidechannel to propagate package ownership.
type file struct {
	path   string
	info   fs.FileInfo
	header *tar.Header
}

func walkFS(ctx context.Context, fsys apkfs.FullFS) iter.Seq2[*file, error] {
	return func(yield func(*file, error) bool) {
		usersFile, _ := passwd.ReadUserFile(fsys, "etc/passwd")
		groupsFile, _ := passwd.ReadGroupFile(fsys, "etc/group")
		users := map[int]string{}
		groups := map[int]string{}
		for _, u := range usersFile.Entries {
			users[int(u.UID)] = u.UserName
		}
		for _, g := range groupsFile.Entries {
			groups[int(g.GID)] = g.GroupName
		}

		if err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			// skip the root path, superfluous
			if path == "." {
				return nil
			}

			if err != nil {
				return err
			}

			info, err := d.Info()
			if err != nil {
				return err
			}

			var link string
			if info.Mode()&os.ModeSymlink == os.ModeSymlink {
				if link, err = fsys.Readlink(path); err != nil {
					return err
				}
			}

			header, err := tar.FileInfoHeader(info, link)
			if err != nil {
				return err
			}

			if info.Mode()&os.ModeCharDevice == os.ModeCharDevice {
				dev, err := fsys.Readnod(path)
				if err != nil {
					return err
				}
				header.Devmajor = int64(unix.Major(uint64(dev)))
				header.Devminor = int64(unix.Minor(uint64(dev)))
			}

			// tar.FileInfoHeader sets Name to the base name of the file,
			// which is weird, because tar.Header.Name is the full path.
			// In some cases, that does make sense, because fs.FileInfo.Name()
			// is only the basename, but in tar.FileInfoHeader, it populates
			// many of the fields based on the fs.FileInfo.Sys() method returning
			// a tar.Header, which _does_ have the full path!
			//
			// Regardless, we want to override the name with the full path, here,
			// because this path represents the full path _as written into this fs_,
			// which might be different from the original tar.Header's full path.
			header.Name = path

			header.ModTime = info.ModTime()

			if name, ok := users[header.Uid]; ok {
				header.Uname = name
			}
			if name, ok := groups[header.Gid]; ok {
				header.Gname = name
			}

			if link != "" {
				header.Typeflag = tar.TypeSymlink
			}

			if header.PAXRecords == nil {
				header.PAXRecords = map[string]string{}
			}

			// only capture xattrs for real objects in the FS
			if header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeDir {
				xattrs, err := fsys.ListXattrs(path)
				// we can ignore errors
				if err == nil && xattrs != nil {
					for name, value := range xattrs {
						header.PAXRecords[xattrTarPAXRecordsPrefix+name] = string(value)
					}
				}
			}

			if !yield(&file{
				path:   path,
				info:   info,
				header: header,
			}, nil) {
				return fs.SkipAll
			}

			return nil
		}); err != nil {
			if !yield(nil, err) {
				return
			}
		}
	}
}
