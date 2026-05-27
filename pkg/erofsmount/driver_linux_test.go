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

//go:build linux

package erofsmount

import (
	"reflect"
	"strings"
	"testing"
)

func TestBuildKernelLayerArgs(t *testing.T) {
	got := buildKernelLayerArgs("/blobs/abc", "/mnt/x")
	want := []string{"mount", "-t", "erofs", "-o", "loop,ro", "/blobs/abc", "/mnt/x"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestBuildFuseLayerArgs(t *testing.T) {
	got := buildFuseLayerArgs("/blobs/abc", "/mnt/x")
	want := []string{"erofsfuse", "/blobs/abc", "/mnt/x"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestBuildKernelOverlayArgs_Writable(t *testing.T) {
	got := buildKernelOverlayArgs(
		[]string{"/mnt/x/layers/02", "/mnt/x/layers/01", "/mnt/x/layers/00"},
		"/mnt/x/upper", "/mnt/x/work", "/mnt/x/merged",
		false,
	)
	want := []string{
		"mount", "-t", "overlay", "-o",
		"lowerdir=/mnt/x/layers/02:/mnt/x/layers/01:/mnt/x/layers/00,upperdir=/mnt/x/upper,workdir=/mnt/x/work",
		"overlay", "/mnt/x/merged",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestBuildKernelOverlayArgs_ReadOnly(t *testing.T) {
	got := buildKernelOverlayArgs(
		[]string{"/a", "/b"},
		"/ignored-upper", "/ignored-work", "/merged",
		true,
	)
	// Read-only must omit upperdir/workdir and append ,ro.
	opts := got[4]
	if strings.Contains(opts, "upperdir") || strings.Contains(opts, "workdir") {
		t.Errorf("read-only overlay should not reference upperdir/workdir: %s", opts)
	}
	if !strings.HasSuffix(opts, ",ro") {
		t.Errorf("read-only overlay opts should end with ,ro: %s", opts)
	}
	if !strings.HasPrefix(opts, "lowerdir=/a:/b") {
		t.Errorf("lowerdir order wrong: %s", opts)
	}
}

func TestBuildFuseOverlayArgs(t *testing.T) {
	got := buildFuseOverlayArgs(
		[]string{"/a", "/b"},
		"/u", "/w", "/m",
		false,
	)
	want := []string{
		"fuse-overlayfs", "-o",
		"lowerdir=/a:/b,upperdir=/u,workdir=/w",
		"/m",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestBuildKernelUmountArgs(t *testing.T) {
	got := buildKernelUmountArgs("/mnt/x")
	want := []string{"umount", "/mnt/x"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestBuildFusermountUmountArgs(t *testing.T) {
	got := buildFusermountUmountArgs("/usr/bin/fusermount3", "/mnt/x")
	want := []string{"/usr/bin/fusermount3", "-u", "/mnt/x"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
