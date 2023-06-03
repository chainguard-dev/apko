package oci_test

import (
	"testing"

	"chainguard.dev/apko/pkg/build/oci"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/log"
	"chainguard.dev/apko/pkg/options"
	"github.com/google/go-cmp/cmp"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/static"
	ggcrtypes "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/require"
)

func TestBuildImageFromLayer(t *testing.T) {
	layer := static.NewLayer([]byte("hello"), ggcrtypes.OCILayer)
	diffID, err := layer.DiffID()
	require.NoError(t, err)

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
				Author:    "apko",
				CreatedBy: "apko",
				Comment:   "This is an apko single-layer image",
			}},
			OS:     "linux",
			RootFS: v1.RootFS{Type: "layers", DiffIDs: []v1.Hash{diffID}},
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
				Author:    "apko",
				CreatedBy: "apko",
				Comment:   "This is an apko single-layer image",
			}},
			OS:     "linux",
			RootFS: v1.RootFS{Type: "layers", DiffIDs: []v1.Hash{diffID}},
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
				Author:    "apko",
				CreatedBy: "apko",
				Comment:   "This is an apko single-layer image",
			}},
			OS:     "linux",
			RootFS: v1.RootFS{Type: "layers", DiffIDs: []v1.Hash{diffID}},
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
				Author:    "apko",
				CreatedBy: "apko",
				Comment:   "This is an apko single-layer image",
			}},
			OS:     "linux",
			RootFS: v1.RootFS{Type: "layers", DiffIDs: []v1.Hash{diffID}},
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
			got, err := oci.BuildImageFromLayer(layer, c.cfg, log.DefaultLogger(), options.Options{})
			require.NoError(t, err)
			gotcfg, err := got.ConfigFile()
			require.NoError(t, err)
			if d := cmp.Diff(c.want, gotcfg); d != "" {
				t.Errorf("ConfigFile() mismatch (-want +got):\n%s", d) //nolint:forbidigo
			}
		})
	}
}
