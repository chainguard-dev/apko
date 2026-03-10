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
	"archive/tar"
	"bytes"
	"fmt"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"gopkg.in/yaml.v3"
)

const (
	XpkgLayerAnnotation      = "io.crossplane.xpkg"
	XpkgLayerAnnotationValue = "base"
)

func generatePackageYAML(xpkg map[string]any) ([]byte, error) {
	data, err := yaml.Marshal(xpkg)
	if err != nil {
		return nil, fmt.Errorf("marshaling xpkg content to YAML: %w", err)
	}
	return data, nil
}

func buildXpkgLayer(content []byte, created time.Time) (v1.Layer, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	hdr := &tar.Header{
		Name:    "package.yaml",
		Mode:    0o644,
		Size:    int64(len(content)),
		ModTime: created,
	}

	if err := tw.WriteHeader(hdr); err != nil {
		return nil, fmt.Errorf("writing tar header for package.yaml: %w", err)
	}

	if _, err := tw.Write(content); err != nil {
		return nil, fmt.Errorf("writing package.yaml content to tar: %w", err)
	}

	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("closing tar writer: %w", err)
	}

	return tarball.LayerFromReader(&buf)
}
