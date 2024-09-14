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

package tarball

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha1" //nolint:gosec
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"syscall"

	"go.opentelemetry.io/otel"
	"golang.org/x/sys/unix"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/apk/passwd"
)

const xattrTarPAXRecordsPrefix = "SCHILY.xattr."

func hasHardlinks(fi fs.FileInfo) bool {
	if stat := fi.Sys(); stat != nil {
		si, ok := stat.(*syscall.Stat_t)
		if !ok {
			return false
		}

		// if we don't have inodes, we just assume the filesystem
		// does not support hardlinks
		if si == nil {
			return false
		}

		return si.Nlink > 1
	}

	return false
}

func getInodeFromFileInfo(fi fs.FileInfo) (uint64, error) {
	if stat := fi.Sys(); stat != nil {
		si, ok := stat.(*syscall.Stat_t)
		if !ok {
			return 0, fmt.Errorf("unable to stat underlying file")
		}

		// if we don't have inodes, we just assume the filesystem
		// does not support hardlinks
		if si == nil {
			return 0, fmt.Errorf("unable to stat underlying file")
		}

		return si.Ino, nil
	}

	return 0, fmt.Errorf("unable to stat underlying file")
}

func (c *Context) writeTar(ctx context.Context, tw *tar.Writer, fsys fs.FS, users, groups map[int]string) error { //nolint:gocyclo
	if users == nil {
		users = map[int]string{}
	}
	if groups == nil {
		groups = map[int]string{}
	}
	seenFiles := map[uint64]string{}
	// set this once, to make it easy to look up later
	if c.overridePerms == nil {
		c.overridePerms = map[string]tar.Header{}
	}

	buf := make([]byte, 1<<20)

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

		var (
			link         string
			major, minor uint32
			isCharDevice bool
		)
		if info.Mode()&os.ModeSymlink == os.ModeSymlink {
			rlfs, ok := fsys.(apkfs.ReadLinkFS)
			if !ok {
				return fmt.Errorf("readlink not supported by this fs: path (%s)", path)
			}

			if link, err = rlfs.Readlink(path); err != nil {
				return err
			}
		}

		if info.Mode()&os.ModeCharDevice == os.ModeCharDevice {
			rlfs, ok := fsys.(apkfs.ReadnodFS)
			if !ok {
				return fmt.Errorf("read character device not supported by this fs: path (%s) %#v %#v", path, info, fsys)
			}
			isCharDevice = true
			dev, err := rlfs.Readnod(path)
			if err != nil {
				return err
			}
			major = unix.Major(uint64(dev))
			minor = unix.Minor(uint64(dev))
		}

		header, err := tar.FileInfoHeader(info, link)
		if err != nil {
			return err
		}
		// devices
		if isCharDevice {
			header.Devmajor = int64(major)
			header.Devminor = int64(minor)
		}
		// work around some weirdness, without this we wind up with just the basename
		header.Name = path

		// zero out timestamps for reproducibility
		header.ModTime = info.ModTime()

		if uid, ok := c.remapUIDs[header.Uid]; ok {
			header.Uid = uid
		}

		if gid, ok := c.remapGIDs[header.Gid]; ok {
			header.Gid = gid
		}

		if name, ok := users[header.Uid]; ok {
			header.Uname = name
		}
		if name, ok := groups[header.Gid]; ok {
			header.Gname = name
		}

		if c.OverrideUIDGID {
			header.Uid = c.UID
			header.Gid = c.GID
		}

		if c.OverrideUname != "" {
			header.Uname = c.OverrideUname
		}

		if c.OverrideGname != "" {
			header.Gname = c.OverrideGname
		}

		// look for the override perms with or without the leading /
		if h, ok := c.overridePerms[header.Name]; ok {
			header.Mode = h.Mode
			header.Uid = h.Uid
			header.Gid = h.Gid
			header.Uname = h.Uname
			header.Gname = h.Gname
		}
		if h, ok := c.overridePerms["/"+header.Name]; ok {
			header.Mode = h.Mode
			header.Uid = h.Uid
			header.Gid = h.Gid
			header.Uname = h.Uname
			header.Gname = h.Gname
		}

		if link != "" {
			header.Typeflag = tar.TypeSymlink
		}
		if !info.IsDir() && hasHardlinks(info) {
			inode, err := getInodeFromFileInfo(info)
			if err != nil {
				return err
			}

			if oldpath, ok := seenFiles[inode]; ok {
				header.Typeflag = tar.TypeLink
				header.Linkname = oldpath
				header.Size = 0
			} else {
				seenFiles[inode] = header.Name
			}
		}

		if header.PAXRecords == nil {
			header.PAXRecords = map[string]string{}
		}
		if c.UseChecksums {
			if link != "" {
				linkDigest := sha1.Sum([]byte(link)) //nolint:gosec
				linkChecksum := hex.EncodeToString(linkDigest[:])
				header.PAXRecords["APK-TOOLS.checksum.SHA1"] = linkChecksum
			} else if info.Mode().IsRegular() {
				data, err := fsys.Open(path)
				if err != nil {
					return err
				}
				defer data.Close()

				fileDigest := sha1.New() //nolint:gosec
				if _, err := io.CopyBuffer(fileDigest, data, buf); err != nil {
					return err
				}

				fileChecksum := hex.EncodeToString(fileDigest.Sum(nil))
				header.PAXRecords["APK-TOOLS.checksum.SHA1"] = fileChecksum
			}
		}

		// only capture xattrs for real objects in the FS
		if header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeDir {
			xfs, ok := fsys.(apkfs.XattrFS)
			if ok {
				xattrs, err := xfs.ListXattrs(path)
				// we can ignore errors
				if err == nil && xattrs != nil {
					for name, value := range xattrs {
						header.PAXRecords[xattrTarPAXRecordsPrefix+name] = string(value)
					}
				}
			}
		}

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		if info.Mode().IsRegular() && header.Size > 0 {
			data, err := fsys.Open(path)
			if err != nil {
				return err
			}

			defer data.Close()

			if _, err := io.CopyBuffer(tw, data, buf); err != nil {
				return err
			}
		}

		return nil
	}); err != nil {
		return err
	}

	return nil
}

// WriteArchive writes a tarball to the provided io.Writer from the provided fs.FS.
// To override permissions, set the OverridePerms when creating the Context.
// If you need to get multiple filesystems, merge them prior to calling WriteArchive.
//
// Deprecated: Use WriteTargz or WriteTar instead.
func (c *Context) WriteArchive(dst io.Writer, src fs.FS) error {
	return c.WriteTargz(context.Background(), dst, src, src)
}

// WriteTargz writes a gzipped tarball to the provided io.Writer from the provided fs.FS.
// To override permissions, set the OverridePerms when creating the Context.
// If you need to get multiple filesystems, merge them prior to calling WriteArchive.
// userinfosrc should be a fs which can provide an optionally provide an etc/passwd and etc/group file.
// The etc/passwd and etc/group file provide username and group name mappings for the tar.
func (c *Context) WriteTargz(ctx context.Context, dst io.Writer, src fs.FS, userinfofs fs.FS) error {
	ctx, span := otel.Tracer("go-apk").Start(ctx, "WriteTargz")
	defer span.End()

	gzw := gzip.NewWriter(dst)
	defer gzw.Close()

	return c.WriteTar(ctx, gzw, src, userinfofs)
}

// WriteTar writes a tarball to the provided io.Writer from the provided fs.FS.
// To override permissions, set the OverridePerms when creating the Context.
// If you need to get multiple filesystems, merge them prior to calling WriteArchive.
// userinfosrc should be a fs which can provide an optionally provide an etc/passwd and etc/group file.
// The etc/passwd and etc/group file provide username and group name mappings for the tar.
func (c *Context) WriteTar(ctx context.Context, dst io.Writer, src fs.FS, userinfosrc fs.FS) error {
	ctx, span := otel.Tracer("go-apk").Start(ctx, "WriteTar")
	defer span.End()

	tw := tar.NewWriter(dst)
	if !c.SkipClose {
		defer tw.Close()
	} else {
		defer tw.Flush()
	}

	// get the uname and gname maps
	usersFile, _ := passwd.ReadUserFile(userinfosrc, "etc/passwd")
	groupsFile, _ := passwd.ReadGroupFile(userinfosrc, "etc/group")
	users := map[int]string{}
	groups := map[int]string{}
	for _, u := range usersFile.Entries {
		users[int(u.UID)] = u.UserName
	}
	for _, g := range groupsFile.Entries {
		groups[int(g.GID)] = g.GroupName
	}
	if err := c.writeTar(ctx, tw, src, users, groups); err != nil {
		return fmt.Errorf("writing TAR archive failed: %w", err)
	}

	return nil
}
