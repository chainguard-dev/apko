package build

import (
	"archive/tar"
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
)

type Package struct {
	Name    string
	Version string
}

func (p Package) String() string {
	return fmt.Sprintf("%s=%s", p.Name, p.Version)
}

func extractFile(image v1.Image, filename string) ([]byte, error) {
	fs := mutate.Extract(image)
	defer fs.Close()
	reader := tar.NewReader(fs)
	for header, err := reader.Next(); err == nil; header, err = reader.Next() {
		fmt.Println("BASE FILE: ", header.Name)
		if header.Name == filename {
			b, err := ioutil.ReadAll(reader)
			return b, err
		}
	}
	return nil, fmt.Errorf("failed to get File")
}

func parseInstalled(installed string) []Package {
	var result []Package
	// Split entries by blank line
	entries := strings.Split(installed, "\n\n")
	for _, entry := range entries {
		lines := strings.Split(entry, "\n")
		var name string
		var version string
		for _, line := range lines {
			if strings.HasPrefix(line, "P:") {
				name = line[2:]
			}
			if strings.HasPrefix(line, "V:") {
				version = line[2:]
			}
		}
		if name != "" {
			result = append(result, Package{name, version})
		}
	}
	return result
}

func GetInstalledPackages(image v1.Image) ([]Package, error) {
	contents, err := extractFile(image, "lib/apk/db/installed")
	if err != nil {
		return nil, err
	}
	return parseInstalled(string(contents[:])), nil
}

func GetImageForArch(image_path string, arch string) (v1.Image, error) {
	index, err := layout.ImageIndexFromPath(image_path)
	if err != nil {
		return nil, err
	}
	index_manifest, err := index.IndexManifest()
	if err != nil {
		return nil, err
	}
	for _, m := range index_manifest.Manifests {
		if m.Platform.Architecture == arch {
			img, err := index.Image(m.Digest)
			if err != nil {
				log.Fatalf("Error: %v", err)
			}
			return img, nil
		}
	}
	return nil, fmt.Errorf("Image for arch not found")
}

func GetInstalledPackagesForArch(image_path string, arch string) ([]Package, error) {
	img, err := GetImageForArch(image_path, arch)
	if err != nil {
		return nil, err
	}
	return GetInstalledPackages(img)
}
