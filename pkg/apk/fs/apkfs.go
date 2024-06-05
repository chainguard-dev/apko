package fs

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"

	"chainguard.dev/apko/pkg/apk/expandapk"
)

type APKFSType int

const (
	APKFSControl APKFSType = iota
	APKFSPackage
)

type APKFS struct {
	path   string
	files  map[string]*apkFSFile
	ctx    context.Context
	cache  *expandapk.APKExpanded
	fsType APKFSType
}

func (a *APKFS) acquireCache() (*expandapk.APKExpanded, error) {
	if a.cache == nil {
		file, err := os.Open(a.path)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		a.cache, err = expandapk.ExpandApk(a.ctx, file, "/tmp/")
		if err != nil {
			return nil, err
		}
	}
	return a.cache, nil
}
func (a *APKFS) getTarReader() (*os.File, *tar.Reader, error) {
	var fileName string
	if a.fsType == APKFSPackage {
		fileName = a.cache.PackageFile
	} else if a.fsType == APKFSControl {
		fileName = a.cache.ControlFile
	}
	file, err := os.Open(fileName)

	if err != nil {
		return nil, nil, err
	}
	gzipStream, err := gzip.NewReader(file)
	if err != nil {
		return nil, nil, err
	}
	tr := tar.NewReader(gzipStream)
	return file, tr, nil
}
func correctMode(mode fs.FileMode, header *tar.Header) fs.FileMode {
	switch header.Typeflag {
	case tar.TypeSymlink:
		mode |= fs.ModeSymlink
	case tar.TypeDir:
		mode |= fs.ModeDir
	}
	return mode
}
func NewAPKFS(ctx context.Context, archive string, apkfsType APKFSType) (*APKFS, error) {
	result := APKFS{archive, make(map[string]*apkFSFile), ctx, nil, apkfsType}

	file, err := os.Open(archive)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	apkExpanded, err := expandapk.ExpandApk(ctx, file, "")
	if err != nil {
		return nil, err
	}
	defer apkExpanded.Close()
	var fileName string
	if result.fsType == APKFSPackage {
		fileName = apkExpanded.PackageFile
	} else if result.fsType == APKFSControl {
		fileName = apkExpanded.ControlFile
	}
	gzipFile, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer gzipFile.Close()
	gzipStream, err := gzip.NewReader(gzipFile)
	if err != nil {
		return nil, err
	}

	reader := tar.NewReader(gzipStream)
	for {
		header, err := reader.Next()

		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		currentEntry := apkFSFile{mode: correctMode(fs.FileMode(header.Mode), header), name: "/" + header.Name,
			uid: header.Uid, gid: header.Gid,
			size: uint64(header.Size), modTime: header.ModTime,
			createTime: header.ChangeTime,
			linkTarget: header.Linkname, isDir: header.Typeflag == tar.TypeDir,
			xattrs: make(map[string][]byte), fs: &result}
		for k, v := range header.PAXRecords {
			// If this trend continues then it would be wise to move the
			// named constant for this into a place accessible from here
			attrname := strings.TrimPrefix(k, "SCHILY.xattr.")
			if len(attrname) != len(k) {
				currentEntry.xattrs[attrname] = []byte(v)
			}
		}
		result.files["/"+header.Name] = &currentEntry
	}

	result.files["/"] = &apkFSFile{mode: 0777 | fs.ModeDir, name: "/",
		uid: 0, gid: 0,
		size: 0, modTime: time.Unix(0, 0),
		createTime: time.Unix(0, 0),
		linkTarget: "", isDir: true,
		xattrs: make(map[string][]byte), fs: &result}
	result.cache, err = result.acquireCache()
	if err != nil {
		return nil, err
	}
	return &result, nil
}
func (a *APKFS) Close() error {
	if a.cache == nil {
		return nil
	}
	return a.cache.Close()
}

type apkFSFile struct {
	mode       fs.FileMode
	uid, gid   int
	name       string
	size       uint64
	modTime    time.Time
	createTime time.Time
	linkTarget string
	linkCount  int
	xattrs     map[string][]byte
	isDir      bool
	fs         *APKFS
	// The following fields are not initialized in the copies held
	// by the apkfs object.
	fileDescriptor io.Closer
	tarReader      *tar.Reader
}

// Users of the api should not handle the copies referred to in the
// filesystem object.
func (a *apkFSFile) acquireCopy() *apkFSFile {
	return &apkFSFile{mode: a.mode, uid: a.uid, gid: a.gid, size: a.size,
		name: a.name, modTime: a.modTime, createTime: a.createTime, linkTarget: a.linkTarget,
		linkCount: a.linkCount, xattrs: a.xattrs, isDir: a.isDir, fs: a.fs,
		fileDescriptor: nil, tarReader: nil}
}
func (a *apkFSFile) seekTo(reader *tar.Reader) error {
	for {
		header, err := reader.Next()
		if err == os.ErrNotExist {
			break
		} else if err != nil {
			return err
		}
		if header.Name == a.name[1:] {
			return nil
		}
	}
	return os.ErrNotExist
}

func (a *apkFSFile) Read(b []byte) (int, error) {
	return a.tarReader.Read(b)
}
func (a *apkFSFile) Stat() (fs.FileInfo, error) {
	return &apkFSFileInfo{file: a, name: a.name}, nil
}
func (a *apkFSFile) Close() error {
	if a.fileDescriptor != nil {
		err := a.fileDescriptor.Close()
		if err != nil {
			return err
		}
	}

	return nil
}

func (a *APKFS) Stat(path string) (fs.FileInfo, error) {
	path = correctApkFSPath(path)
	file, ok := a.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	onlyName := file.name[strings.LastIndex(file.name, "/"):]
	info := &apkFSFileInfo{file: file, name: onlyName}
	return info, nil
}
func correctApkFSPath(path string) string {
	if path == "." {
		path = "/"
	}
	if len(path) > 3 && path[:2] == "./" {
		path = path[1:]
	}

	if len(path) < 1 || path[0:1] != "/" {
		path = "/" + path
	}

	return path
}
func (a *APKFS) ReadDir(path string) ([]fs.DirEntry, error) {
	path = correctApkFSPath(path)
	file, ok := a.files[path]
	if !ok {
		return nil, fs.ErrNotExist
	}
	if !file.isDir {
		return nil, fs.ErrInvalid
	}
	results := make([]fs.DirEntry, 0)
	for currentPath, currentFile := range a.files {
		if path == currentPath {
			continue
		}
		pathPrefix := path
		if path != "/" {
			pathPrefix += "/"
		}
		if strings.HasPrefix(currentPath, pathPrefix) {
			if strings.LastIndex(currentPath, "/") > len(path)+1 {
				// some sub-sub directory, not yet
				continue
			}
			results = append(results, &apkFSFileInfo{currentFile, currentPath[strings.LastIndex(currentPath, "/"):]})
		}
	}
	return results, nil
}

func (a *APKFS) Open(path string) (fs.File, error) {
	path = correctApkFSPath(path)
	file, ok := a.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}

	fileCopy := file.acquireCopy()
	var err error
	fileCopy.fileDescriptor, fileCopy.tarReader, err = a.getTarReader()
	if err != nil {
		return nil, err
	}
	err = fileCopy.seekTo(fileCopy.tarReader)
	if err != nil {
		return nil, err
	}
	return fileCopy, nil
}

type apkFSFileInfo struct {
	file *apkFSFile
	name string
}

func (a *apkFSFileInfo) Name() string {
	return a.file.name[strings.LastIndex(a.file.name, "/")+1:]
}
func (a *apkFSFileInfo) Size() int64 {
	return int64(a.file.size)
}
func (a *apkFSFileInfo) Mode() fs.FileMode {
	return a.file.mode
}
func (a *apkFSFileInfo) Type() fs.FileMode {
	return a.Mode()
}
func (a *apkFSFileInfo) Info() (fs.FileInfo, error) {
	return a, nil
}
func (a *apkFSFileInfo) ModTime() time.Time {
	return a.file.modTime
}
func (a *apkFSFileInfo) IsDir() bool {
	return a.file.isDir
}
func (a *apkFSFileInfo) Sys() any {
	return &tar.Header{
		Mode: int64(a.file.mode),
		Uid:  a.file.uid,
		Gid:  a.file.gid,
	}
}
