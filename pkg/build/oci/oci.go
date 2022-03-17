// Copyright 2022 Chainguard, Inc.
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

package oci

import (
	"fmt"
	"io"
	"log"
	"sort"
	"time"

	ecr "github.com/awslabs/amazon-ecr-credential-helper/ecr-login"
	"github.com/chrismellard/docker-credential-acr-env/pkg/credhelper"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/authn/github"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/google"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	v1tar "github.com/google/go-containerregistry/pkg/v1/tarball"

	"chainguard.dev/apko/pkg/build/types"
)

var keychain = authn.NewMultiKeychain(
	authn.DefaultKeychain,
	google.Keychain,
	authn.NewKeychainFromHelper(ecr.NewECRHelper(ecr.WithLogOutput(io.Discard))),
	authn.NewKeychainFromHelper(credhelper.NewACRCredentialsHelper()),
	github.Keychain,
)

func buildImageFromLayer(layerTarGZ string, ic types.ImageConfiguration, created time.Time, arch types.Architecture, logger *log.Logger) (v1.Image, error) {
	logger.Printf("building OCI image from layer '%s'", layerTarGZ)

	v1Layer, err := v1tar.LayerFromFile(layerTarGZ)
	if err != nil {
		return empty.Image, fmt.Errorf("failed to create OCI layer from tar.gz: %w", err)
	}

	digest, err := v1Layer.Digest()
	if err != nil {
		return empty.Image, fmt.Errorf("could not calculate layer digest: %w", err)
	}

	diffid, err := v1Layer.DiffID()
	if err != nil {
		return empty.Image, fmt.Errorf("could not calculate layer diff id: %w", err)
	}

	logger.Printf("OCI layer digest: %v", digest)
	logger.Printf("OCI layer diffID: %v", diffid)

	adds := make([]mutate.Addendum, 0, 1)
	adds = append(adds, mutate.Addendum{
		Layer: v1Layer,
		History: v1.History{
			Author:    "apko",
			Comment:   "This is an apko single-layer image",
			CreatedBy: "apko",
			Created:   v1.Time{Time: created},
		},
	})

	v1Image, err := mutate.Append(empty.Image, adds...)
	if err != nil {
		return empty.Image, fmt.Errorf("unable to append OCI layer to empty image: %w", err)
	}

	cfg, err := v1Image.ConfigFile()
	if err != nil {
		return empty.Image, fmt.Errorf("unable to get OCI config file: %w", err)
	}

	cfg = cfg.DeepCopy()
	cfg.Author = "github.com/chainguard-dev/apko"
	cfg.Architecture = arch.String()
	cfg.OS = "linux"

	if ic.Entrypoint.Command != "" {
		cfg.Config.Entrypoint = []string{"/bin/sh", "-c", ic.Entrypoint.Command}
	} else {
		cfg.Config.Entrypoint = []string{"/bin/sh", "-l"}
	}

	if ic.Accounts.RunAs != "" {
		cfg.Config.User = ic.Accounts.RunAs
	}

	v1Image, err = mutate.ConfigFile(v1Image, cfg)
	if err != nil {
		return empty.Image, fmt.Errorf("unable to update OCI config file: %w", err)
	}

	return v1Image, nil
}

func BuildImageTarballFromLayer(imageRef string, layerTarGZ string, outputTarGZ string, ic types.ImageConfiguration, created time.Time, arch types.Architecture, logger *log.Logger) error {
	v1Image, err := buildImageFromLayer(layerTarGZ, ic, created, arch, logger)
	if err != nil {
		return err
	}

	imgRefTag, err := name.NewTag(imageRef)
	if err != nil {
		return fmt.Errorf("unable to validate image reference tag: %w", err)
	}

	if err := v1tar.WriteToFile(outputTarGZ, imgRefTag, v1Image); err != nil {
		return fmt.Errorf("unable to write OCI image to disk: %w", err)
	}

	logger.Printf("output OCI image file to %s", outputTarGZ)
	return nil
}

func publishTagFromImage(image v1.Image, imageRef string, hash v1.Hash) (name.Digest, error) {
	imgRef, err := name.ParseReference(imageRef)
	if err != nil {
		return name.Digest{}, fmt.Errorf("unable to parse reference: %w", err)
	}

	if err := remote.Write(imgRef, image, remote.WithAuthFromKeychain(keychain)); err != nil {
		return name.Digest{}, fmt.Errorf("failed to publish: %w", err)
	}
	return imgRef.Context().Digest(hash.String()), nil
}

func PublishImageFromLayer(layerTarGZ string, ic types.ImageConfiguration, created time.Time, arch types.Architecture, logger *log.Logger, tags ...string) (name.Digest, v1.Image, error) {
	v1Image, err := buildImageFromLayer(layerTarGZ, ic, created, arch, logger)
	if err != nil {
		return name.Digest{}, nil, err
	}

	h, err := v1Image.Digest()
	if err != nil {
		return name.Digest{}, nil, fmt.Errorf("failed to compute digest: %w", err)
	}

	digest := name.Digest{}
	for _, tag := range tags {
		logger.Printf("publishing tag %v", tag)
		digest, err = publishTagFromImage(v1Image, tag, h)
		if err != nil {
			return name.Digest{}, nil, err
		}
	}

	return digest, v1Image, nil
}

func PublishIndex(imgs map[types.Architecture]v1.Image, logger *log.Logger, tags ...string) (name.Digest, error) {
	var idx v1.ImageIndex = empty.Index
	archs := make([]types.Architecture, 0, len(imgs))
	for arch := range imgs {
		archs = append(archs, arch)
	}
	sort.Slice(archs, func(i, j int) bool {
		return archs[i].String() < archs[j].String()
	})
	for _, arch := range archs {
		img := imgs[arch]
		mt, err := img.MediaType()
		if err != nil {
			return name.Digest{}, fmt.Errorf("failed to get mediatype: %w", err)
		}

		h, err := img.Digest()
		if err != nil {
			return name.Digest{}, fmt.Errorf("failed to compute digest: %w", err)
		}

		size, err := img.Size()
		if err != nil {
			return name.Digest{}, fmt.Errorf("failed to compute size: %w", err)
		}

		idx = mutate.AppendManifests(idx, mutate.IndexAddendum{
			Add: img,
			Descriptor: v1.Descriptor{
				MediaType: mt,
				Digest:    h,
				Size:      size,
				Platform:  arch.ToOCIPlatform(),
			},
		})
	}

	h, err := idx.Digest()
	if err != nil {
		return name.Digest{}, err
	}

	digest := name.Digest{}
	for _, tag := range tags {
		logger.Printf("publishing tag %v", tag)
		digest, err = publishTagFromIndex(idx, tag, h)
		if err != nil {
			return name.Digest{}, err
		}
	}

	return digest, nil
}

func publishTagFromIndex(index v1.ImageIndex, imageRef string, hash v1.Hash) (name.Digest, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return name.Digest{}, fmt.Errorf("unable to parse reference: %w", err)
	}

	err = remote.WriteIndex(ref, index, remote.WithAuthFromKeychain(keychain))
	if err != nil {
		return name.Digest{}, fmt.Errorf("failed to publish: %w", err)
	}
	return ref.Context().Digest(hash.String()), nil
}
