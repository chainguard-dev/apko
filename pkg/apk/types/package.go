package types

import (
	"encoding/base64"
	"fmt"
	"io"
	"time"

	"gopkg.in/ini.v1"
)

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
	Triggers         []string `ini:"triggers,,allowshadow"`
}

// AsPackage converts PackageInfo to a Package struct with the given controlHash and size.
func (pkginfo *PackageInfo) AsPackage(controlHash []byte, size uint64) *Package {
	return &Package{
		Name:             pkginfo.Name,
		Version:          pkginfo.Version,
		Arch:             pkginfo.Arch,
		Description:      pkginfo.Description,
		License:          pkginfo.License,
		Origin:           pkginfo.Origin,
		Maintainer:       pkginfo.Maintainer,
		URL:              pkginfo.URL,
		Dependencies:     pkginfo.Dependencies,
		Provides:         pkginfo.Provides,
		InstallIf:        pkginfo.InstallIf,
		InstalledSize:    pkginfo.Size,
		ProviderPriority: pkginfo.ProviderPriority,
		BuildDate:        pkginfo.BuildDate,
		RepoCommit:       pkginfo.RepoCommit,
		Replaces:         pkginfo.Replaces,
		DataHash:         pkginfo.DataHash,
		Triggers:         pkginfo.Triggers,

		BuildTime: time.Unix(pkginfo.BuildDate, 0).UTC(),
		Checksum:  controlHash,
		Size:      size,
	}
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
	Triggers         []string `ini:"triggers,,allowshadow"`
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

// ParsePackageInfo parses the given reader containing the contents of a .PKGINFO
// file and returns a PackageInfo struct.
func ParsePackageInfo(info io.Reader) (*PackageInfo, error) {
	cfg, err := ini.ShadowLoad(info)
	if err != nil {
		return nil, fmt.Errorf("ini.ShadowLoad(): %w", err)
	}

	pkg := new(PackageInfo)
	if err = cfg.MapTo(pkg); err != nil {
		return nil, fmt.Errorf("cfg.MapTo(): %w", err)
	}
	return pkg, nil
}
