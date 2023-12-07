package build

import (
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/lock"
	"fmt"
	"github.com/chainguard-dev/go-apk/pkg/apk"
)

type installablePackage struct {
	name     string
	url      string
	checksum string
}

func (p installablePackage) URL() string { return p.url }

func (p installablePackage) PackageName() string { return p.name }

func (p installablePackage) ChecksumString() string { return p.checksum }

func installablePackagesForArch(l lock.Lock, arch types.Architecture) ([]apk.InstallablePackage, error) {
	pkgs := make([]apk.InstallablePackage, len(l.Contents.Packages))
	for i, p := range l.Contents.Packages {
		if p.Checksum == "" {
			return nil, fmt.Errorf("locked package %s has missing checksum (please regenerate the lock file (resolved-file) with Apko >=0.12)", p.Name)
		}
		pkgs[i] = installablePackage{name: p.Name, url: p.URL, checksum: p.Checksum}
	}
	return pkgs, nil
}
