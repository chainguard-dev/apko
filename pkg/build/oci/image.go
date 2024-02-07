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

package oci

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	v1tar "github.com/google/go-containerregistry/pkg/v1/tarball"
	ggcrtypes "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/google/shlex"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/signed"
	"golang.org/x/exp/maps"

	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/options"
)

func BuildImageFromLayer(ctx context.Context, layer v1.Layer, ic types.ImageConfiguration, created time.Time, arch types.Architecture) (oci.SignedImage, error) {
	log := clog.FromContext(ctx)

	mediaType, err := layer.MediaType()
	if err != nil {
		return nil, fmt.Errorf("accessing layer MediaType: %w", err)
	}
	imageType := humanReadableImageType(mediaType)
	log.Debug("building image from layer")

	digest, err := layer.Digest()
	if err != nil {
		return nil, fmt.Errorf("could not calculate layer digest: %w", err)
	}

	diffid, err := layer.DiffID()
	if err != nil {
		return nil, fmt.Errorf("could not calculate layer diff id: %w", err)
	}

	log.Infof("%s layer digest: %v", imageType, digest)
	log.Infof("%s layer diffID: %v", imageType, diffid)

	adds := make([]mutate.Addendum, 0, 1)
	adds = append(adds, mutate.Addendum{
		Layer: layer,
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

	annotations := ic.Annotations
	if annotations == nil {
		annotations = map[string]string{}
	}
	if ic.VCSUrl != "" {
		if url, hash, ok := strings.Cut(ic.VCSUrl, "@"); ok {
			annotations["org.opencontainers.image.source"] = url
			annotations["org.opencontainers.image.revision"] = hash
		}
	}

	if mediaType != ggcrtypes.DockerLayer && len(annotations) > 0 {
		v1Image = mutate.Annotations(v1Image, annotations).(v1.Image)
	}

	cfg, err := v1Image.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("unable to get %s config file: %w", imageType, err)
	}

	cfg = cfg.DeepCopy()
	cfg.Author = "github.com/chainguard-dev/apko"
	platform := arch.ToOCIPlatform()
	cfg.Architecture = platform.Architecture
	cfg.Variant = platform.Variant
	cfg.Created = v1.Time{Time: created}
	cfg.Config.Labels = make(map[string]string)
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

	if ic.WorkDir != "" {
		cfg.Config.WorkingDir = ic.WorkDir
	}

	if ic.Volumes != nil {
		cfg.Config.Volumes = make(map[string]struct{})
		for _, v := range ic.Volumes {
			cfg.Config.Volumes[v] = struct{}{}
		}
	}

	env := maps.Clone(ic.Environment)
	// Set these environment variables if they are not already set.
	if env == nil {
		env = map[string]string{}
	}
	for k, v := range map[string]string{
		"PATH":          "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt",
	} {
		if _, found := env[k]; !found {
			env[k] = v
		}
	}
	envs := []string{}
	for k, v := range env {
		envs = append(envs, fmt.Sprintf("%s=%s", k, v))
	}
	sort.Strings(envs)
	cfg.Config.Env = envs

	if ic.Accounts.RunAs != "" {
		cfg.Config.User = ic.Accounts.RunAs
	}

	if ic.StopSignal != "" {
		cfg.Config.StopSignal = ic.StopSignal
	}

	v1Image, err = mutate.ConfigFile(v1Image, cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to update %s config file: %w", imageType, err)
	}

	si := signed.Image(v1Image)
	return si, nil
}

func BuildImageTarballFromLayer(ctx context.Context, imageRef string, layer v1.Layer, outputTarGZ string, ic types.ImageConfiguration, opts options.Options) error {
	log := clog.FromContext(ctx)
	v1Image, err := BuildImageFromLayer(ctx, layer, ic, opts.SourceDateEpoch, opts.Arch)
	if err != nil {
		return err
	}

	if v1Image == nil {
		return errors.New("image build from layer returned nil")
	}
	imgRefTag, err := name.NewTag(imageRef)
	if err != nil {
		return fmt.Errorf("unable to validate image reference tag: %w", err)
	}

	if err := v1tar.WriteToFile(outputTarGZ, imgRefTag, v1Image); err != nil {
		return fmt.Errorf("unable to write image to disk: %w", err)
	}

	log.Infof("output image file to %s", outputTarGZ)
	return nil
}
