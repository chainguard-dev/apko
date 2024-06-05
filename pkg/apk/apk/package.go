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

package apk

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1" //nolint:gosec // this is what apk tools is using
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"strings"
	"time"

	"gopkg.in/ini.v1"

	"chainguard.dev/apko/pkg/apk/expandapk"
)

// PackageToInstalled takes a Package and returns it as the string representation of lines in a /lib/apk/db/installed file.
func PackageToInstalled(pkg *Package) (out []string) {
	out = append(out, fmt.Sprintf("P:%s", pkg.Name))
	out = append(out, fmt.Sprintf("V:%s", pkg.Version))
	out = append(out, fmt.Sprintf("A:%s", pkg.Arch))
	out = append(out, fmt.Sprintf("L:%s", pkg.License))
	out = append(out, fmt.Sprintf("T:%s", pkg.Description))
	out = append(out, fmt.Sprintf("o:%s", pkg.Origin))
	out = append(out, fmt.Sprintf("m:%s", pkg.Maintainer))
	out = append(out, fmt.Sprintf("U:%s", pkg.URL))
	out = append(out, fmt.Sprintf("D:%s", strings.Join(pkg.Dependencies, " ")))
	out = append(out, fmt.Sprintf("p:%s", strings.Join(pkg.Provides, " ")))
	if len(pkg.Replaces) != 0 {
		out = append(out, fmt.Sprintf("r:%s", strings.Join(pkg.Replaces, " ")))
	}
	out = append(out, fmt.Sprintf("c:%s", pkg.RepoCommit))
	out = append(out, fmt.Sprintf("i:%s", pkg.InstallIf))
	out = append(out, fmt.Sprintf("t:%d", pkg.BuildTime.Unix()))
	out = append(out, fmt.Sprintf("S:%d", pkg.Size))
	out = append(out, fmt.Sprintf("I:%d", pkg.InstalledSize))
	out = append(out, fmt.Sprintf("k:%d", pkg.ProviderPriority))
	if len(pkg.Checksum) > 0 {
		out = append(out, fmt.Sprintf("C:%s", pkg.ChecksumString()))
	}

	return
}

// InstallablePackage represents a minimal set of information needed to install a package within an Image.
type InstallablePackage interface {
	URL() string
	PackageName() string
	ChecksumString() string
}

// PackageInfo represents the information present in .PKGINFO.
type PackageInfo struct {
	Name             string   `ini:"pkgname"`
	Version          string   `ini:"pkgver"`
	Arch             string   `ini:"arch"`
	Description      string   `ini:"pkgdesc"`
	License          string   `ini:"license"`
	Origin           string   `ini:"origin"`
	Maintainer       string   `ini:"maintainer"`
	URL              string   `ini:"url"`
	Dependencies     []string `ini:"depend,,allowshadow"`
	Provides         []string `ini:"provides,,allowshadow"`
	InstallIf        []string `ini:"install_if,,allowshadow"`
	Size             uint64   `ini:"size"`
	ProviderPriority uint64   `ini:"provider_priority"`
	BuildDate        int64    `ini:"builddate"`
	RepoCommit       string   `ini:"commit"`
	Replaces         []string `ini:"replaces,,allowshadow"`
	DataHash         string   `ini:"datahash"`
}

// Package represents a single package with the information present in an
// APKINDEX.
type Package struct {
	Name             string `ini:"pkgname"`
	Version          string `ini:"pkgver"`
	Arch             string `ini:"arch"`
	Description      string `ini:"pkgdesc"`
	License          string `ini:"license"`
	Origin           string `ini:"origin"`
	Maintainer       string `ini:"maintainer"`
	URL              string `ini:"url"`
	Checksum         []byte
	Dependencies     []string `ini:"depend,,allowshadow"`
	Provides         []string `ini:"provides,,allowshadow"`
	InstallIf        []string
	Size             uint64 `ini:"size"`
	InstalledSize    uint64
	ProviderPriority uint64 `ini:"provider_priority"`
	BuildTime        time.Time
	BuildDate        int64    `ini:"builddate"`
	RepoCommit       string   `ini:"commit"`
	Replaces         []string `ini:"replaces,,allowshadow"`
	DataHash         string   `ini:"datahash"`
}

func (p *Package) String() string {
	return fmt.Sprintf("%s (ver:%s arch:%s)", p.Name, p.Version, p.Arch)
}
func (p *Package) PackageName() string { return p.Name }

// Filename returns the package filename as it's named in a repository.
func (p *Package) Filename() string {
	// Note: Doesn't use fmt.Sprintf because we call this a lot when we disqualify images.
	return p.Name + "-" + p.Version + ".apk"
}

// ChecksumString returns a human-readable version of the control section checksum.
func (p *Package) ChecksumString() string {
	return "Q1" + base64.StdEncoding.EncodeToString(p.Checksum)
}

// ParsePackage parses a .apk file and returns a Package struct
func ParsePackage(ctx context.Context, apkPackage io.Reader, size uint64) (*Package, error) {
	pkginfo, h, err := ParsePackageInfo(apkPackage)
	if err != nil {
		return nil, err
	}

	return &Package{
		Name:             pkginfo.Name,
		Version:          pkginfo.Version,
		Arch:             pkginfo.Arch,
		Description:      pkginfo.Description,
		License:          pkginfo.License,
		Origin:           pkginfo.Origin,
		Maintainer:       pkginfo.Maintainer,
		URL:              pkginfo.URL,
		Checksum:         h.Sum(nil),
		Dependencies:     pkginfo.Dependencies,
		Provides:         pkginfo.Provides,
		InstallIf:        pkginfo.InstallIf,
		Size:             size,
		InstalledSize:    pkginfo.Size,
		ProviderPriority: pkginfo.ProviderPriority,
		BuildTime:        time.Unix(pkginfo.BuildDate, 0).UTC(),
		BuildDate:        pkginfo.BuildDate,
		RepoCommit:       pkginfo.RepoCommit,
		Replaces:         pkginfo.Replaces,
		DataHash:         pkginfo.DataHash,
	}, nil
}

// ParsePackageInfo returns a parsed .PKGINFO from an APK reader and the control section hash.
func ParsePackageInfo(apkPackage io.Reader) (*PackageInfo, hash.Hash, error) {
	split, err := expandapk.Split(apkPackage)
	if err != nil {
		return nil, nil, fmt.Errorf("splitting apk: %w", err)
	}
	control := split[0]
	if len(split) == 3 {
		// signature section is present
		control = split[1]
	}

	b, err := io.ReadAll(control)
	if err != nil {
		return nil, nil, err
	}

	h := sha1.New() //nolint:gosec
	if _, err = h.Write(b); err != nil {
		return nil, nil, err
	}

	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, nil, err
	}

	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if err != nil {
			return nil, nil, fmt.Errorf("did not see .PKGINFO in APK: %w", err)
		}

		if hdr.Name == ".PKGINFO" {
			cfg, err := ini.ShadowLoad(tr)
			if err != nil {
				return nil, nil, fmt.Errorf("ini.ShadowLoad(): %w", err)
			}

			pkg := new(PackageInfo)
			if err = cfg.MapTo(pkg); err != nil {
				return nil, nil, fmt.Errorf("cfg.MapTo(): %w", err)
			}

			return pkg, h, nil
		}
	}
}
