//nolint:all
package apk

import "chainguard.dev/apko/pkg/apk/expandapk"

type APKResolved struct {
	Package *RepositoryPackage

	SignatureSize int64
	SignatureHash []byte

	ControlSize int64
	ControlHash []byte

	DataSize int64
	DataHash []byte
}

func NewAPKResolved(pkg *RepositoryPackage, expanded *expandapk.APKExpanded) *APKResolved {
	return &APKResolved{
		Package:       pkg,
		ControlSize:   expanded.ControlSize,
		ControlHash:   expanded.ControlHash,
		SignatureHash: expanded.SignatureHash,
		SignatureSize: expanded.SignatureSize,
		DataHash:      expanded.PackageHash,
		DataSize:      expanded.PackageSize,
	}
}
