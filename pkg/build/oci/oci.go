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
	"io/ioutil"
	"log"
	"runtime"
	"time"

	"chainguard.dev/apko/pkg/build/types"
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
	"github.com/pkg/errors"
)

func buildImageFromLayer(layerTarGZ string, ic types.ImageConfiguration) (v1.Image, error) {
	log.Printf("building OCI image from layer '%s'", layerTarGZ)

	v1Layer, err := v1tar.LayerFromFile(layerTarGZ)
	if err != nil {
		return empty.Image, errors.Wrap(err, "failed to create OCI layer from tar.gz")
	}

	digest, err := v1Layer.Digest()
	if err != nil {
		return empty.Image, errors.Wrap(err, "could not calculate layer digest")
	}

	diffid, err := v1Layer.DiffID()
	if err != nil {
		return empty.Image, errors.Wrap(err, "could not calculate layer diff id")
	}

	log.Printf("OCI layer digest: %v", digest)
	log.Printf("OCI layer diffID: %v", diffid)

	adds := make([]mutate.Addendum, 0, 1)
	adds = append(adds, mutate.Addendum{
		Layer: v1Layer,
		History: v1.History{
			Author:    "apko",
			Comment:   "This is an apko single-layer image",
			CreatedBy: "apko",
			Created:   v1.Time{Time: time.Now()},
		},
	})

	v1Image, err := mutate.Append(empty.Image, adds...)
	if err != nil {
		return empty.Image, errors.Wrap(err, "unable to append OCI layer to empty image")
	}

	cfg, err := v1Image.ConfigFile()
	if err != nil {
		return empty.Image, errors.Wrap(err, "unable to get OCI config file")
	}

	cfg = cfg.DeepCopy()
	cfg.Author = "github.com/chainguard-dev/apko"
	cfg.Architecture = runtime.GOARCH
	cfg.OS = runtime.GOOS

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
		return empty.Image, errors.Wrap(err, "unable to update OCI config file")
	}

	return v1Image, nil
}

func BuildImageTarballFromLayer(imageRef string, layerTarGZ string, outputTarGZ string, ic types.ImageConfiguration) error {
	v1Image, err := buildImageFromLayer(layerTarGZ, ic)
	if err != nil {
		return err
	}

	imgRefTag, err := name.NewTag(imageRef)
	if err != nil {
		return errors.Wrap(err, "unable to validate image reference tag")
	}

	err = v1tar.WriteToFile(outputTarGZ, imgRefTag, v1Image)
	if err != nil {
		return errors.Wrap(err, "unable to write OCI image to disk")
	}

	log.Printf("output OCI image file to %s", outputTarGZ)
	return nil
}

func publishTagFromImage(image v1.Image, imageRef string, hash v1.Hash, kc authn.Keychain) (name.Digest, error) {
	imgRef, err := name.ParseReference(imageRef)
	if err != nil {
		return name.Digest{}, errors.Wrap(err, "unable to parse reference")
	}

	err = remote.Write(imgRef, image, remote.WithAuthFromKeychain(kc))
	if err != nil {
		return name.Digest{}, errors.Wrap(err, "failed to publish")
	}
	return imgRef.Context().Digest(hash.String()), nil
}

func PublishImageFromLayer(layerTarGZ string, ic types.ImageConfiguration, tags ...string) (name.Digest, error) {
	v1Image, err := buildImageFromLayer(layerTarGZ, ic)
	if err != nil {
		return name.Digest{}, err
	}

	h, err := v1Image.Digest()
	if err != nil {
		return name.Digest{}, errors.Wrap(err, "failed to compute digest")
	}

	kc := authn.NewMultiKeychain(
		authn.DefaultKeychain,
		google.Keychain,
		authn.NewKeychainFromHelper(ecr.NewECRHelper(ecr.WithLogOutput(ioutil.Discard))),
		authn.NewKeychainFromHelper(credhelper.NewACRCredentialsHelper()),
		github.Keychain,
	)

	digest := name.Digest{}
	for _, tag := range tags {
		log.Printf("publishing tag %v", tag)
		digest, err = publishTagFromImage(v1Image, tag, h, kc)
		if err != nil {
			return name.Digest{}, err
		}
	}

	return digest, nil
}
