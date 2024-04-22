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

package baseimg

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path"

	"github.com/chainguard-dev/go-apk/pkg/apk"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	ocitypes "github.com/google/go-containerregistry/pkg/v1/types"

	"chainguard.dev/apko/pkg/build/types"
)

type BaseImage struct {
	img                       v1.Image
	apkIndex                  []byte
	materizalizedApkIndexPath string
	arch                      types.Architecture
}

// See https://github.com/opencontainers/image-spec/blob/main/image-index.md#image-index-property-descriptions
// Briefly: index.json can either list manifest of per arch images, or redirect to actual image index (nested case)
func getUnnestedImageIndex(imgPath string) (v1.ImageIndex, error) {
	index, err := layout.ImageIndexFromPath(imgPath)
	if err != nil {
		return nil, err
	}
	indexManifest, err := index.IndexManifest()
	if err != nil {
		return nil, err
	}
	for _, m := range indexManifest.Manifests {
		if m.MediaType == ocitypes.OCIImageIndex {
			return index.ImageIndex(m.Digest)
		}
	}
	return index, nil
}

func getImageForArch(imgPath string, arch types.Architecture) (v1.Image, error) {
	index, err := getUnnestedImageIndex(imgPath)
	if err != nil {
		return nil, err
	}
	indexManifest, err := index.IndexManifest()
	if err != nil {
		return nil, err
	}

	for _, m := range indexManifest.Manifests {
		img, err := index.Image(m.Digest)
		if err != nil {
			return nil, err
		}
		config, err := img.ConfigFile()
		if err != nil {
			return nil, err
		}
		if config == nil {
			return nil, fmt.Errorf("got image without config")
		}
		if config.Architecture == arch.ToOCIPlatform().Architecture {
			return img, nil
		}
	}
	return nil, fmt.Errorf("image for arch not found")
}

// New creates an instance of BaseImage base on provided parameters:
//   - imgPath: path to the directory containing OCI layout of the image.
//   - apkIndexPath: path to the directory containing per arch APKINDEX files representing
//     installed file of the base image.
//   - arch: architecture of the base image.
//   - materializedApkIndexPath: path where the auxiliary APKINDEX of the base image will be written to in order to
//     resolve packages.
func New(imgPath string, apkIndexPath string, arch types.Architecture, materizalizedApkIndexPath string) (*BaseImage, error) {
	img, err := getImageForArch(imgPath, arch)
	if err != nil {
		return nil, err
	}
	contents, err := os.ReadFile(path.Join(apkIndexPath, arch.ToAPK(), "APKINDEX"))
	if err != nil {
		return nil, err
	}
	baseImg := BaseImage{
		img:                       img,
		apkIndex:                  contents,
		materizalizedApkIndexPath: materizalizedApkIndexPath,
		arch:                      arch,
	}
	err = baseImg.createAPKIndexArchive(baseImg.APKIndexPath())
	if err != nil {
		return nil, err
	}
	return &baseImg, nil
}

func (baseImg *BaseImage) Image() v1.Image {
	return baseImg.img
}

func (baseImg *BaseImage) InstalledPackages() ([]*apk.InstalledPackage, error) {
	reader := bytes.NewReader(baseImg.apkIndex)
	return apk.ParseInstalled(reader)
}

func (baseImg *BaseImage) APKIndexPath() string {
	return path.Join(baseImg.materizalizedApkIndexPath, "base_image_apkindex")
}

func (baseImg *BaseImage) createAPKIndexArchive(apkIndexTargetPath string) error {
	archDir := path.Join(apkIndexTargetPath, baseImg.arch.ToAPK())
	if err := os.MkdirAll(archDir, 0777); err != nil {
		return err
	}
	tarFile, err := os.OpenFile(path.Join(archDir, "APKINDEX.tar.gz"), os.O_CREATE|os.O_WRONLY, 0777)
	if err != nil {
		return err
	}
	defer tarFile.Close()
	gzipWriter := gzip.NewWriter(tarFile)
	defer gzipWriter.Close()
	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()
	header := tar.Header{Name: "APKINDEX", Size: int64(len(baseImg.apkIndex)), Mode: 0777}
	if err := tarWriter.WriteHeader(&header); err != nil {
		return err
	}
	if _, err := tarWriter.Write(baseImg.apkIndex); err != nil {
		return err
	}
	return nil
}
