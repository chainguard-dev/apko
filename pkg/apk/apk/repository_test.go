package apk

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewRepositoryFromComponentsBuildsCorrectUri(t *testing.T) {
	repo := NewRepositoryFromComponents(
		"https://dl-cdn.alpinelinux.org/alpine",
		"edge",
		"main",
		"x86_64",
	)

	assert.Equal(t, "https://dl-cdn.alpinelinux.org/alpine/edge/main/x86_64", repo.URI)
}

func TestRepositoryPackageReturnsCorrectUrl(t *testing.T) {
	pkg := RepositoryPackage{
		Package: &Package{
			Name:    "test-package",
			Version: "1.2.3-r0",
		},
		repository: &RepositoryWithIndex{
			Repository: &Repository{
				URI: "https://dl-cdn.alpinelinux.org/alpine/edge/main/x86_64",
			},
		},
	}

	assert.Equal(t, "https://dl-cdn.alpinelinux.org/alpine/edge/main/x86_64/test-package-1.2.3-r0.apk", pkg.URL())
}
