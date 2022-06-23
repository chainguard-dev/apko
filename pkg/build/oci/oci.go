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
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/avast/retry-go"
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
	"github.com/google/shlex"
	"github.com/sigstore/cosign/pkg/oci"
	ocimutate "github.com/sigstore/cosign/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/sigstore/cosign/pkg/oci/signed"
	"github.com/sigstore/cosign/pkg/oci/static"
	"github.com/sigstore/cosign/pkg/oci/walk"
	ctypes "github.com/sigstore/cosign/pkg/types"
	"github.com/sirupsen/logrus"

	"chainguard.dev/apko/pkg/build/types"
)

var keychain = authn.NewMultiKeychain(
	authn.DefaultKeychain,
	google.Keychain,
	authn.NewKeychainFromHelper(ecr.NewECRHelper(ecr.WithLogger(io.Discard))),
	authn.NewKeychainFromHelper(credhelper.NewACRCredentialsHelper()),
	github.Keychain,
)

func buildImageFromLayerWithMediaType(mediaType ggcrtypes.MediaType, layerTarGZ string, ic types.ImageConfiguration, created time.Time, arch types.Architecture, logger *logrus.Entry, sbomPath string, sbomFormats []string) (oci.SignedImage, error) {
	imageType := humanReadableImageType(mediaType)
	logger.Printf("building %s image from layer '%s'", imageType, layerTarGZ)

	v1Layer, err := v1tar.LayerFromFile(layerTarGZ, v1tar.WithMediaType(mediaType))
	if err != nil {
		return nil, fmt.Errorf("failed to create %s layer from tar.gz: %w", imageType, err)
	}

	digest, err := v1Layer.Digest()
	if err != nil {
		return nil, fmt.Errorf("could not calculate layer digest: %w", err)
	}

	diffid, err := v1Layer.DiffID()
	if err != nil {
		return nil, fmt.Errorf("could not calculate layer diff id: %w", err)
	}

	logger.Printf("%s layer digest: %v", imageType, digest)
	logger.Printf("%s layer diffID: %v", imageType, diffid)

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

	emptyImage := empty.Image
	if mediaType == ggcrtypes.OCILayer {
		// If building an OCI layer, then we should assume OCI manifest and config too
		emptyImage = mutate.MediaType(emptyImage, ggcrtypes.OCIManifestSchema1)
		emptyImage = mutate.ConfigMediaType(emptyImage, ggcrtypes.OCIConfigJSON)
	}
	v1Image, err := mutate.Append(emptyImage, adds...)
	if err != nil {
		return nil, fmt.Errorf("unable to append %s layer to empty image: %w", imageType, err)
	}

	cfg, err := v1Image.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("unable to get %s config file: %w", imageType, err)
	}

	cfg = cfg.DeepCopy()
	cfg.Author = "github.com/chainguard-dev/apko"
	cfg.Architecture = arch.String()
	cfg.Created = v1.Time{Time: created}
	cfg.OS = "linux"

	// NOTE: Need to allow empty Entrypoints. The runtime will override to `/bin/sh -c` and handle quoting
	switch {
	case ic.Entrypoint.ShellFragment != "":
		cfg.Config.Entrypoint = []string{"/bin/sh", "-c", ic.Entrypoint.ShellFragment}
	case ic.Entrypoint.Command != "":
		splitcmd, err := shlex.Split(ic.Entrypoint.Command)
		if err != nil {
			return nil, fmt.Errorf("unable to parse entrypoint command: %w", err)
		}
		cfg.Config.Entrypoint = splitcmd
	}

	if ic.Cmd != "" {
		splitcmd, err := shlex.Split(ic.Cmd)
		if err != nil {
			return nil, fmt.Errorf("unable to parse cmd: %w", err)
		}
		cfg.Config.Cmd = splitcmd
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
		return nil, fmt.Errorf("unable to update %s config file: %w", imageType, err)
	}

	si := signed.Image(v1Image)

	// Attach the SBOM, e.g.
	// TODO(kaniini): Allow all SBOM types to be uploaded.
	if len(sbomFormats) > 0 {
		var mt ggcrtypes.MediaType
		var path string
		switch sbomFormats[0] {
		case "spdx":
			mt = ctypes.SPDXJSONMediaType
			path = filepath.Join(sbomPath, fmt.Sprintf("sbom-%s.spdx.json", arch.ToAPK()))
		case "cyclonedx":
			mt = ctypes.CycloneDXJSONMediaType
			path = filepath.Join(sbomPath, fmt.Sprintf("sbom-%s.cdx", arch.ToAPK()))
		case "idb":
			mt = "application/vnd.apko.installed-db"
			path = filepath.Join(sbomPath, fmt.Sprintf("sbom-%s.idb", arch.ToAPK()))
		default:
			return nil, fmt.Errorf("unsupported SBOM format: %s", sbomFormats[0])
		}
		if len(sbomFormats) > 1 {
			// When we have multiple formats, warn that we're picking the first.
			logger.Printf("WARNING: multiple SBOM formats requested, uploading SBOM with media type: %s", mt)
		}

		sbom, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading sbom: %w", err)
		}

		f, err := static.NewFile(sbom, static.WithLayerMediaType(mt))
		if err != nil {
			return nil, err
		}
		si, err = ocimutate.AttachFileToImage(si, "sbom", f)
		if err != nil {
			return nil, err
		}
	}

	return si, nil
}

func BuildImageTarballFromLayer(imageRef string, layerTarGZ string, outputTarGZ string, ic types.ImageConfiguration, created time.Time, arch types.Architecture, logger *logrus.Entry) error {
	return buildImageTarballFromLayerWithMediaType(ggcrtypes.OCILayer, imageRef, layerTarGZ, outputTarGZ, ic, created, arch, logger)
}

func BuildDockerImageTarballFromLayer(imageRef string, layerTarGZ string, outputTarGZ string, ic types.ImageConfiguration, created time.Time, arch types.Architecture, logger *logrus.Entry) error {
	return buildImageTarballFromLayerWithMediaType(ggcrtypes.DockerLayer, imageRef, layerTarGZ, outputTarGZ, ic, created, arch, logger)
}

func buildImageTarballFromLayerWithMediaType(mediaType ggcrtypes.MediaType, imageRef string, layerTarGZ string, outputTarGZ string, ic types.ImageConfiguration, created time.Time, arch types.Architecture, logger *logrus.Entry) error {
	imageType := humanReadableImageType(mediaType)
	v1Image, err := buildImageFromLayerWithMediaType(mediaType, layerTarGZ, ic, created, arch, logger, "", nil)
	if err != nil {
		return err
	}

	imgRefTag, err := name.NewTag(imageRef)
	if err != nil {
		return fmt.Errorf("unable to validate image reference tag: %w", err)
	}

	if err := v1tar.WriteToFile(outputTarGZ, imgRefTag, v1Image); err != nil {
		return fmt.Errorf("unable to write %s image to disk: %w", imageType, err)
	}

	logger.Printf("output %s image file to %s", imageType, outputTarGZ)
	return nil
}

func publishTagFromImage(image oci.SignedImage, imageRef string, hash v1.Hash, logger *logrus.Entry) (name.Digest, error) {
	imgRef, err := name.ParseReference(imageRef)
	if err != nil {
		return name.Digest{}, fmt.Errorf("unable to parse reference: %w", err)
	}

	// Write any attached SBOMs/signatures.
	wp := writePeripherals(imgRef, logger, remote.WithAuthFromKeychain(keychain))
	if err := wp(context.Background(), image); err != nil {
		return name.Digest{}, err
	}

	if err := retry.Do(func() error {
		return remote.Write(imgRef, image, remote.WithAuthFromKeychain(keychain))
	}); err != nil {
		return name.Digest{}, fmt.Errorf("failed to publish: %w", err)
	}
	return imgRef.Context().Digest(hash.String()), nil
}

func PublishImageFromLayer(layerTarGZ string, ic types.ImageConfiguration, created time.Time, arch types.Architecture, logger *logrus.Entry, sbomPath string, sbomFormats []string, tags ...string) (name.Digest, oci.SignedImage, error) {
	return publishImageFromLayerWithMediaType(ggcrtypes.OCILayer, layerTarGZ, ic, created, arch, logger, sbomPath, sbomFormats, tags...)
}

func PublishDockerImageFromLayer(layerTarGZ string, ic types.ImageConfiguration, created time.Time, arch types.Architecture, logger *logrus.Entry, sbomPath string, sbomFormats []string, tags ...string) (name.Digest, oci.SignedImage, error) {
	return publishImageFromLayerWithMediaType(ggcrtypes.DockerLayer, layerTarGZ, ic, created, arch, logger, sbomPath, sbomFormats, tags...)
}

func publishImageFromLayerWithMediaType(mediaType ggcrtypes.MediaType, layerTarGZ string, ic types.ImageConfiguration, created time.Time, arch types.Architecture, logger *logrus.Entry, sbomPath string, sbomFormats []string, tags ...string) (name.Digest, oci.SignedImage, error) {
	v1Image, err := buildImageFromLayerWithMediaType(mediaType, layerTarGZ, ic, created, arch, logger, sbomPath, sbomFormats)
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
		digest, err = publishTagFromImage(v1Image, tag, h, logger)
		if err != nil {
			return name.Digest{}, nil, err
		}
	}

	return digest, v1Image, nil
}

func PublishIndex(imgs map[types.Architecture]oci.SignedImage, logger *logrus.Entry, tags ...string) (name.Digest, error) {
	return publishIndexWithMediaType(ggcrtypes.OCIImageIndex, imgs, logger, tags...)
}

func PublishDockerIndex(imgs map[types.Architecture]oci.SignedImage, logger *logrus.Entry, tags ...string) (name.Digest, error) {
	return publishIndexWithMediaType(ggcrtypes.DockerManifestList, imgs, logger, tags...)
}

func publishIndexWithMediaType(mediaType ggcrtypes.MediaType, imgs map[types.Architecture]oci.SignedImage, logger *logrus.Entry, tags ...string) (name.Digest, error) {
	idx := signed.ImageIndex(mutate.IndexMediaType(empty.Index, mediaType))
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
		digest, err = publishTagFromIndex(idx, tag, h, logger)
		if err != nil {
			return name.Digest{}, err
		}
	}

	return digest, nil
}

func publishTagFromIndex(index oci.SignedImageIndex, imageRef string, hash v1.Hash, logger *logrus.Entry) (name.Digest, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return name.Digest{}, fmt.Errorf("unable to parse reference: %w", err)
	}

	// Write any attached SBOMs/signatures (recursively)
	wp := writePeripherals(ref, logger, remote.WithAuthFromKeychain(keychain))
	if err := walk.SignedEntity(context.Background(), index, wp); err != nil {
		return name.Digest{}, err
	}

	if err := retry.Do(func() error {
		return remote.WriteIndex(ref, index, remote.WithAuthFromKeychain(keychain))
	}); err != nil {
		return name.Digest{}, fmt.Errorf("failed to publish: %w", err)
	}
	return ref.Context().Digest(hash.String()), nil
}

func writePeripherals(tag name.Reference, logger *logrus.Entry, opt ...remote.Option) walk.Fn {
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

		f, err := se.Attachment("sbom")
		if err != nil {
			// Some levels (e.g. the index) may not have an SBOM,
			// just like some levels may not have signatures/attestations.
			return nil
		}

		if err := retry.Do(func() error {
			return remote.Write(ref, f, opt...)
		}); err != nil {
			return fmt.Errorf("writing sbom: %w", err)
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
		logger.Printf("Published SBOM %v", ref)

		return nil
	}
}

func humanReadableImageType(mediaType ggcrtypes.MediaType) string {
	switch mediaType {
	case ggcrtypes.DockerLayer:
		return "Docker"
	case ggcrtypes.OCILayer:
		return "OCI"
	}
	return "unknown"
}
