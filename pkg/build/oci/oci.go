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
	"log"
	"runtime"
	"time"

	"chainguard.dev/apko/pkg/build/types"
	"github.com/pkg/errors"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	v1tar "github.com/google/go-containerregistry/pkg/v1/tarball"
)

func BuildImageRefFromLayer(imageRef string, layerTarGZ string, outputTarGZ string, ic types.ImageConfiguration) error {
	log.Printf("building OCI image '%s' from layer '%s'", imageRef, layerTarGZ)

	v1Layer, err := v1tar.LayerFromFile(layerTarGZ)
	if err != nil {
		return errors.Wrap(err, "failed to create OCI layer from tar.gz")
	}

	digest, err := v1Layer.Digest()
	if err != nil {
		return errors.Wrap(err, "could not calculate layer digest")
	}

	diffid, err := v1Layer.DiffID()
	if err != nil {
		return errors.Wrap(err, "could not calculate layer diff id")
	}

	log.Printf("OCI layer digest: %v", digest)
	log.Printf("OCI layer diffID: %v", diffid)

	adds := make([]mutate.Addendum, 0, 1)
	adds = append(adds, mutate.Addendum{
		Layer: v1Layer,
		History: v1.History{
			Author: "apko",
			Comment: "This is an apko single-layer image",
			CreatedBy: "apko",
			Created: v1.Time{Time: time.Now()},
		},
	})

	v1Image, err := mutate.Append(empty.Image, adds...)
	if err != nil {
		return errors.Wrap(err, "unable to append OCI layer to empty image")
	}

	imgRefTag, err := name.NewTag(imageRef)
	if err != nil {
		return errors.Wrap(err, "unable to validate image reference tag")
	}

	cfg, err := v1Image.ConfigFile()
	if err != nil {
		return errors.Wrap(err, "unable to get OCI config file")
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

	v1Image, err = mutate.ConfigFile(v1Image, cfg)
	if err != nil {
		return errors.Wrap(err, "unable to update OCI config file")
	}

	err = v1tar.WriteToFile(outputTarGZ, imgRefTag, v1Image)
	if err != nil {
		return errors.Wrap(err, "unable to write OCI image to disk")
	}

	log.Printf("output OCI image file to %s", outputTarGZ)

	return nil
}
