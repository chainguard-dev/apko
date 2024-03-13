// Copyright 2023 Chainguard, Inc.
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
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/static"
	ggcrtypes "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/build/types"
)

func TestBuildImageFromLayer(t *testing.T) {
	layer := static.NewLayer([]byte("hello"), ggcrtypes.OCILayer)
	diffID, err := layer.DiffID()
	require.NoError(t, err)
	now := time.Now()
	v1now := v1.Time{Time: now}

	for _, c := range []struct {
		desc string
		cfg  types.ImageConfiguration
		want *v1.ConfigFile
	}{{
		desc: "no envs",
		cfg: types.ImageConfiguration{
			Environment: map[string]string{},
		},
		want: &v1.ConfigFile{
			Author: "github.com/chainguard-dev/apko",
			History: []v1.History{{
				Created:   v1now,
				Author:    "apko",
				CreatedBy: "apko",
				Comment:   "This is an apko single-layer image",
			}},
			Created: v1now,
			OS:      "linux",
			RootFS:  v1.RootFS{Type: "layers", DiffIDs: []v1.Hash{diffID}},
			Config: v1.Config{
				Env: []string{
					"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
					"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt",
				},
				Labels: map[string]string{},
			},
		},
	}, {
		desc: "some envs",
		cfg: types.ImageConfiguration{
			Environment: map[string]string{
				"FOO": "bar",
			},
		},
		want: &v1.ConfigFile{
			Author: "github.com/chainguard-dev/apko",
			History: []v1.History{{
				Created:   v1now,
				Author:    "apko",
				CreatedBy: "apko",
				Comment:   "This is an apko single-layer image",
			}},
			Created: v1now,
			OS:      "linux",
			RootFS:  v1.RootFS{Type: "layers", DiffIDs: []v1.Hash{diffID}},
			Config: v1.Config{
				Env: []string{
					"FOO=bar",
					"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
					"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt",
				},
				Labels: map[string]string{},
			},
		},
	}, {
		desc: "override default env",
		cfg: types.ImageConfiguration{
			Environment: map[string]string{
				"FOO":  "bar",
				"PATH": "/something/else:/another/one:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			},
		},
		want: &v1.ConfigFile{
			Author: "github.com/chainguard-dev/apko",
			History: []v1.History{{
				Created:   v1now,
				Author:    "apko",
				CreatedBy: "apko",
				Comment:   "This is an apko single-layer image",
			}},
			Created: v1now,
			OS:      "linux",
			RootFS:  v1.RootFS{Type: "layers", DiffIDs: []v1.Hash{diffID}},
			Config: v1.Config{
				Env: []string{
					"FOO=bar",
					"PATH=/something/else:/another/one:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
					"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt",
				},
				Labels: map[string]string{},
			},
		},
	}, {
		desc: "unset default env",
		cfg: types.ImageConfiguration{
			Environment: map[string]string{
				"FOO":  "bar",
				"PATH": "",
			},
		},
		want: &v1.ConfigFile{
			Author: "github.com/chainguard-dev/apko",
			History: []v1.History{{
				Created:   v1now,
				Author:    "apko",
				CreatedBy: "apko",
				Comment:   "This is an apko single-layer image",
			}},
			Created: v1now,
			OS:      "linux",
			RootFS:  v1.RootFS{Type: "layers", DiffIDs: []v1.Hash{diffID}},
			Config: v1.Config{
				Env: []string{
					"FOO=bar",
					"PATH=",
					"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt",
				},
				Labels: map[string]string{},
			},
		},
	}} {
		t.Run(c.desc, func(t *testing.T) {
			ctx := context.Background()
			emptyImg := empty.Image
			got, err := BuildImageFromLayer(ctx, emptyImg, layer, c.cfg, now, types.ParseArchitecture(""))
			require.NoError(t, err)
			gotcfg, err := got.ConfigFile()
			require.NoError(t, err)
			if d := cmp.Diff(c.want, gotcfg); d != "" {
				t.Errorf("ConfigFile() mismatch (-want +got):\n%s", d) //nolint:forbidigo
			}
		})
	}
}

func TestBuildImageTarballFromLayer(t *testing.T) {

}
