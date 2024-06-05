package apk

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/MakeNowJust/heredoc/v2"
)

const apkIndexFilename = "APKINDEX"
const descriptionFilename = "DESCRIPTION"

// Go template for generating the APKINDEX file from an ApkIndex struct
var apkIndexTemplate = template.Must(template.New(apkIndexFilename).Funcs(
	template.FuncMap{
		// Helper function to join slice of string by space
		"join": func(s []string) string {
			return strings.Join(s, " ")
		},
	}).Parse(heredoc.Doc(`C:{{.ChecksumString}}
		P:{{.Name}}
		V:{{.Version}}
		{{- if .Arch}}
		A:{{.Arch}}
		{{- end }}
		{{- if .Size}}
		S:{{.Size}}
		{{- end }}
		{{- if .InstalledSize}}
		I:{{.InstalledSize}}
		{{- end}}
		T:{{.Description}}
		{{- if .URL}}
		U:{{.URL}}
		{{- end}}
		{{- if .License}}
		L:{{.License}}
		{{- end}}
		{{- if .Origin}}
		o:{{.Origin}}
		{{- end}}
		{{- if .Maintainer}}
		m:{{.Maintainer}}
		{{- end}}
		{{- if and .BuildTime (not .BuildTime.IsZero)}}
		t:{{.BuildTime.Unix}}
		{{- end}}
		{{- if .RepoCommit}}
		c:{{.RepoCommit}}
		{{- end}}
		{{- if .Dependencies}}
		D:{{join .Dependencies}}
		{{- end}}
		{{- if .InstallIf}}
		i:{{.InstallIf}}
		{{- end}}
		{{- if .Provides}}
		p:{{join .Provides}}
		{{- end}}
		{{- if .ProviderPriority}}
		k:{{.ProviderPriority}}
		{{- end}}

	`)))

type APKIndex struct { //nolint:revive
	Signature   []byte
	Description string
	Packages    []*Package
}

// Splitting empty string results in single element array with one empty string, which would
// be treated as package with empty name.
func splitRepeatedField(val string) []string {
	if val == "" {
		return nil
	}
	return strings.Split(val, " ")
}

// ParsePackageIndex parses a plain (uncompressed) APKINDEX file. It returns an
// ApkIndex struct
func ParsePackageIndex(apkIndexUnpacked io.Reader) ([]*Package, error) {
	if closer, ok := apkIndexUnpacked.(io.Closer); ok {
		defer closer.Close()
	}

	indexScanner := bufio.NewScanner(apkIndexUnpacked)

	// We have seen alpine's community/coq package a provides line with 72KB of data in it.
	// The default MaxScanTokenSize for bufio.Scanner is 64KB. We allow buf to allocate up
	// to 1MB but give it a starting buffer size of 16KB (default is 4KB) because we always
	// end up having to resize, and 16KB should avoid an extra alloc, whereas the 1MB allows
	// us to alloc enough to handle alpine (and hopefully we never have to revisit this).
	buf := make([]byte, 16*1024)
	meg := 1024 * 1024
	indexScanner.Buffer(buf, meg)

	pkg := &Package{}
	linenr := 1

	packages := []*Package{}
	for indexScanner.Scan() {
		line := indexScanner.Text()
		if len(line) == 0 {
			if pkg.Name != "" {
				packages = append(packages, pkg)
			}
			pkg = &Package{}
			continue
		}

		if len(line) > 1 && line[1:2] != ":" {
			return nil, fmt.Errorf("cannot parse line %d: expected \":\" in not found", linenr)
		}

		token := line[:1]
		val := line[2:]

		switch token {
		case "P":
			pkg.Name = val
		case "V":
			pkg.Version = val
		case "A":
			pkg.Arch = val
		case "L":
			pkg.License = val
		case "T":
			pkg.Description = val
		case "o":
			pkg.Origin = val
		case "m":
			pkg.Maintainer = val
		case "U":
			pkg.URL = val
		case "D":
			pkg.Dependencies = splitRepeatedField(val)
		case "p":
			pkg.Provides = splitRepeatedField(val)
		case "c":
			pkg.RepoCommit = val
		case "t":
			i, err := strconv.ParseInt(val, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("cannot parse build time %s: %w", val, err)
			}
			pkg.BuildDate = i
			pkg.BuildTime = time.Unix(i, 0).UTC()
		case "i":
			pkg.InstallIf = splitRepeatedField(val)
		case "S":
			size, err := strconv.ParseUint(val, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("cannot parse size field %s: %w", val, err)
			}
			pkg.Size = size
		case "I":
			installedSize, err := strconv.ParseUint(val, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("cannot parse installed size field %s: %w", val, err)
			}
			pkg.InstalledSize = installedSize
		case "k":
			priority, err := strconv.ParseUint(val, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("cannot parse provider priority field %s: %w", val, err)
			}
			pkg.ProviderPriority = priority
		case "C":
			// Handle SHA1 checksums:
			if strings.HasPrefix(val, "Q1") {
				checksum, err := base64.StdEncoding.DecodeString(val[2:])
				if err != nil {
					return nil, err
				}
				pkg.Checksum = checksum
			}
		}

		linenr++
	}

	return packages, indexScanner.Err()
}

func IndexFromArchive(archive io.ReadCloser) (*APKIndex, error) {
	gzipReader, err := gzip.NewReader(archive)
	if err != nil {
		return nil, err
	}

	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)
	apkindex := &APKIndex{}

	for {
		hdr, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}

		switch hdr.Name {
		case apkIndexFilename:
			apkindex.Packages, err = ParsePackageIndex(io.NopCloser(tarReader))
			if err != nil {
				return nil, err
			}
		case descriptionFilename:
			description, err := io.ReadAll(tarReader)
			if err != nil {
				return nil, err
			}
			apkindex.Description = string(description)
		default:
			if strings.HasPrefix(hdr.Name, ".SIGN.") {
				var err error
				apkindex.Signature, err = io.ReadAll(tarReader)
				if err != nil {
					return nil, err
				}
			} else {
				return nil, fmt.Errorf("unexpected file found in APKINDEX: %s", hdr.Name)
			}
		}
	}

	return apkindex, nil
}

func ArchiveFromIndex(apkindex *APKIndex) (archive io.Reader, err error) {
	// Execute the template and append output for each package in the index
	var apkindexContents bytes.Buffer
	for _, pkg := range apkindex.Packages {
		if len(pkg.Name) == 0 {
			continue
		}
		err = apkIndexTemplate.Execute(&apkindexContents, pkg)
		if err != nil {
			return nil, fmt.Errorf("failed to parse template for package %s: %w", pkg.Name, err)
		}
	}

	// Create the tarball
	var tarballContents bytes.Buffer
	gw := gzip.NewWriter(&tarballContents)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

	// Add APKINDEX and DESCRIPTION files to the tarball
	for _, item := range []struct {
		filename string
		contents []byte
	}{
		{apkIndexFilename, apkindexContents.Bytes()},
		{descriptionFilename, []byte(apkindex.Description)},
	} {
		var info os.FileInfo = &tarballItemFileInfo{item.filename, int64(len(item.contents))}
		header, err := tar.FileInfoHeader(info, item.filename)
		if err != nil {
			return nil, fmt.Errorf("creating tar header for %s: %w", item.filename, err)
		}
		header.Name = item.filename
		if err := tw.WriteHeader(header); err != nil {
			return nil, fmt.Errorf("writing tar header for %s: %w", item.filename, err)
		}
		if _, err = io.Copy(tw, bytes.NewReader(item.contents)); err != nil {
			return nil, fmt.Errorf("copying tar contents for %s: %w", item.filename, err)
		}
	}

	// Return io.ReadCloser representing the tarball
	return &tarballContents, nil
}

// This type implements os.FileInfo, allowing us to construct
// a tar header without needing to run os.Stat on a file
type tarballItemFileInfo struct {
	name string
	size int64
}

func (info *tarballItemFileInfo) Name() string       { return info.name }
func (info *tarballItemFileInfo) Size() int64        { return info.size }
func (info *tarballItemFileInfo) Mode() os.FileMode  { return 0644 }
func (info *tarballItemFileInfo) ModTime() time.Time { return time.Time{} }
func (info *tarballItemFileInfo) IsDir() bool        { return false }
func (info *tarballItemFileInfo) Sys() interface{}   { return nil }

var _ os.FileInfo = (*tarballItemFileInfo)(nil)
