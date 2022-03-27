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
	"context"
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
	ggcrtypes "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/cosign/pkg/oci"
	ocimutate "github.com/sigstore/cosign/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/sigstore/cosign/pkg/oci/signed"
	"github.com/sigstore/cosign/pkg/oci/walk"

	"chainguard.dev/apko/pkg/build/types"
)

var keychain = authn.NewMultiKeychain(
	authn.DefaultKeychain,
	google.Keychain,
	authn.NewKeychainFromHelper(ecr.NewECRHelper(ecr.WithLogOutput(io.Discard))),
	authn.NewKeychainFromHelper(credhelper.NewACRCredentialsHelper()),
	github.Keychain,
)

func buildImageFromLayer(layerTarGZ string, ic types.ImageConfiguration, created time.Time, arch types.Architecture, logger *log.Logger) (oci.SignedImage, error) {
	logger.Printf("building OCI image from layer '%s'", layerTarGZ)

	v1Layer, err := v1tar.LayerFromFile(layerTarGZ)
	if err != nil {
		return nil, fmt.Errorf("failed to create OCI layer from tar.gz: %w", err)
	}

	digest, err := v1Layer.Digest()
	if err != nil {
		return nil, fmt.Errorf("could not calculate layer digest: %w", err)
	}

	diffid, err := v1Layer.DiffID()
	if err != nil {
		return nil, fmt.Errorf("could not calculate layer diff id: %w", err)
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
		return nil, fmt.Errorf("unable to append OCI layer to empty image: %w", err)
	}

	cfg, err := v1Image.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("unable to get OCI config file: %w", err)
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

	if len(ic.Environment) > 0 {
		envs := []string{}

		for k, v := range ic.Environment {
			envs = append(envs, fmt.Sprintf("%s=%s", k, v))
		}

		cfg.Config.Env = envs
	} else {
		cfg.Config.Env = []string{
			"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt",
		}
	}

	if ic.Accounts.RunAs != "" {
		cfg.Config.User = ic.Accounts.RunAs
	}

	v1Image, err = mutate.ConfigFile(v1Image, cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to update OCI config file: %w", err)
	}

	si := signed.Image(v1Image)

	// TODO(#145): Attach the SBOM, e.g.
	// f, err := static.NewFile(sbom, static.WithLayerMediaType(mt))
	// if err != nil {
	// 	return nil, err
	// }
	// si, err = ocimutate.AttachFileToImage(si, "sbom", f)
	// if err != nil {
	// 	return nil, err
	// }

	return si, nil
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

func publishTagFromImage(image oci.SignedImage, imageRef string, hash v1.Hash) (name.Digest, error) {
	imgRef, err := name.ParseReference(imageRef)
	if err != nil {
		return name.Digest{}, fmt.Errorf("unable to parse reference: %w", err)
	}

	// Write any attached SBOMs/signatures.
	wp := writePeripherals(imgRef, remote.WithAuthFromKeychain(keychain))
	if err := wp(context.Background(), image); err != nil {
		return name.Digest{}, err
	}

	if err := remote.Write(imgRef, image, remote.WithAuthFromKeychain(keychain)); err != nil {
		return name.Digest{}, fmt.Errorf("failed to publish: %w", err)
	}
	return imgRef.Context().Digest(hash.String()), nil
}

func PublishImageFromLayer(layerTarGZ string, ic types.ImageConfiguration, created time.Time, arch types.Architecture, logger *log.Logger, tags ...string) (name.Digest, oci.SignedImage, error) {
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

func PublishIndex(imgs map[types.Architecture]oci.SignedImage, logger *log.Logger, tags ...string) (name.Digest, error) {
	idx := signed.ImageIndex(mutate.IndexMediaType(empty.Index, ggcrtypes.DockerManifestList))
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

		idx = ocimutate.AppendManifests(idx, ocimutate.IndexAddendum{
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

func publishTagFromIndex(index oci.SignedImageIndex, imageRef string, hash v1.Hash) (name.Digest, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return name.Digest{}, fmt.Errorf("unable to parse reference: %w", err)
	}

	// Write any attached SBOMs/signatures (recursively)
	wp := writePeripherals(ref, remote.WithAuthFromKeychain(keychain))
	if err := walk.SignedEntity(context.Background(), index, wp); err != nil {
		return name.Digest{}, err
	}

	err = remote.WriteIndex(ref, index, remote.WithAuthFromKeychain(keychain))
	if err != nil {
		return name.Digest{}, fmt.Errorf("failed to publish: %w", err)
	}
	return ref.Context().Digest(hash.String()), nil
}

func writePeripherals(tag name.Reference, opt ...remote.Option) walk.Fn {
	ociOpts := []ociremote.Option{ociremote.WithRemoteOptions(opt...)}

	// Respect COSIGN_REPOSITORY
	targetRepoOverride, err := ociremote.GetEnvTargetRepository()
	if err != nil {
		return func(ctx context.Context, se oci.SignedEntity) error { return err }
	}
	if (targetRepoOverride != name.Repository{}) {
		ociOpts = append(ociOpts, ociremote.WithTargetRepository(targetRepoOverride))
	}

	return func(ctx context.Context, se oci.SignedEntity) error {
		h, err := se.(interface{ Digest() (v1.Hash, error) }).Digest()
		if err != nil {
			return err
		}

		// TODO(mattmoor): We should have a WriteSBOM helper upstream.
		digest := tag.Context().Digest(h.String()) // Don't *get* the tag, we know the digest
		ref, err := ociremote.SBOMTag(digest, ociOpts...)
		if err != nil {
			return err
		}
		if f, err := se.Attachment("sbom"); err != nil {
			// Some levels (e.g. the index) may not have an SBOM,
			// just like some levels may not have signatures/attestations.
		} else if err := remote.Write(ref, f, opt...); err != nil {
			return fmt.Errorf("writing sbom: %w", err)
		} else {
			log.Printf("Published SBOM %v", ref)
		}

		// TODO(mattmoor): Don't enable this until we start signing or it
		// will publish empty signatures!
		// if err := ociremote.WriteSignatures(tag.Context(), se, ociOpts...); err != nil {
		// 	return err
		// }

		// TODO(mattmoor): Are there any attestations we want to write?
		// if err := ociremote.WriteAttestations(tag.Context(), se, ociOpts...); err != nil {
		// 	return err
		// }
		return nil
	}
}
