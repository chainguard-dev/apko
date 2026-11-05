// Copyright 2026 Chainguard, Inc.
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

package cpio

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"math"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/static"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	urootcpio "github.com/u-root/u-root/pkg/cpio"
)

func TestFromLayerPreservesUIDGID(t *testing.T) {
	const uid, gid = 10001, 10002

	var input bytes.Buffer
	tw := tar.NewWriter(&input)
	headers := []*tar.Header{
		{
			Name:     "srv/state/",
			Typeflag: tar.TypeDir,
			Mode:     0o750,
			Uid:      uid,
			Gid:      gid,
		},
		{
			Name:     "srv/state/config",
			Typeflag: tar.TypeReg,
			Mode:     0o640,
			Uid:      uid,
			Gid:      gid,
			Size:     4,
		},
		{
			Name:     "srv/state/link",
			Typeflag: tar.TypeSymlink,
			Linkname: "config",
			Mode:     0o777,
			Uid:      uid,
			Gid:      gid,
		},
		{
			Name:     "dev/nullish",
			Typeflag: tar.TypeChar,
			Mode:     0o666,
			Uid:      uid,
			Gid:      gid,
			Devmajor: 1,
			Devminor: 3,
		},
		{
			Name:     "root-owned",
			Typeflag: tar.TypeReg,
			Mode:     0o644,
			Uid:      0,
			Gid:      0,
			Size:     3,
		},
	}
	for _, hdr := range headers {
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if hdr.Typeflag == tar.TypeReg {
			payload := "data"
			if hdr.Name == "root-owned" {
				payload = "own"
			}
			if _, err := tw.Write([]byte(payload)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	layer := static.NewLayer(input.Bytes(), v1types.OCIUncompressedLayer)
	var output bytes.Buffer
	if err := FromLayer(layer, &output); err != nil {
		t.Fatal(err)
	}

	reader := urootcpio.Newc.Reader(bytes.NewReader(output.Bytes()))
	want := map[string][2]uint64{
		"srv/state":        {uid, gid},
		"srv/state/config": {uid, gid},
		"srv/state/link":   {uid, gid},
		"dev/nullish":      {uid, gid},
		"root-owned":       {0, 0},
	}
	seen := make(map[string]bool, len(want))
	for {
		rec, err := reader.ReadRecord()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		expected, ok := want[rec.Name]
		if !ok {
			continue
		}
		seen[rec.Name] = true
		if rec.UID != expected[0] || rec.GID != expected[1] {
			t.Errorf("%s: got uid:gid %d:%d; want %d:%d",
				rec.Name, rec.UID, rec.GID, expected[0], expected[1])
		}
	}
	for path := range want {
		if !seen[path] {
			t.Errorf("missing output CPIO entry %q", path)
		}
	}
}

func TestFromLayerRejectsInvalidOwnership(t *testing.T) {
	tests := []struct {
		name string
		uid  int
		gid  int
		want string
	}{
		{name: "negative uid", uid: -1, gid: 100, want: "negative uid/gid"},
		{name: "negative gid", uid: 100, gid: -1, want: "negative uid/gid"},
		{name: "uid past newc", uid: math.MaxUint32 + 1, gid: 1, want: "outside newc range"},
		{name: "gid past newc", uid: 1, gid: math.MaxUint32 + 1, want: "outside newc range"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var input bytes.Buffer
			tw := tar.NewWriter(&input)
			hdr := &tar.Header{
				Name:     "bad-owner",
				Typeflag: tar.TypeReg,
				Mode:     0o644,
				Uid:      tt.uid,
				Gid:      tt.gid,
				Size:     1,
			}
			if err := tw.WriteHeader(hdr); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write([]byte("x")); err != nil {
				t.Fatal(err)
			}
			if err := tw.Close(); err != nil {
				t.Fatal(err)
			}

			layer := static.NewLayer(input.Bytes(), v1types.OCIUncompressedLayer)
			err := FromLayer(layer, io.Discard)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got error %q; want substring %q", err.Error(), tt.want)
			}
		})
	}
}
