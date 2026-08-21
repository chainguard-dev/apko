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
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The kernel umount is the attempt that fails for the interesting reason
// (EBUSY, say), and Unmount is also the blob fall-back, so losing it behind
// whatever fusermount says next would misreport why the unmount failed.
func TestFuseDriverUnmountReportsBothFailures(t *testing.T) {
	// An empty PATH makes the fusermount half fail; the kernel half fails on
	// its own because the path is not a mountpoint.
	t.Setenv("PATH", t.TempDir())

	mp := filepath.Join(t.TempDir(), "not-a-mountpoint")
	if err := os.Mkdir(mp, 0o755); err != nil {
		t.Fatal(err)
	}
	err := (&fuseDriver{}).Unmount(context.Background(), mp)
	if err == nil {
		t.Fatal("Unmount succeeded on a path that is not mounted")
	}
	for _, want := range []string{"umount " + mp, "neither fusermount3 nor fusermount"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

// This pins the wording, not the flag: unmounting a symlink to a directory
// that is not a mountpoint fails either way, so no unprivileged test can tell
// UMOUNT_NOFOLLOW from its absence. hack/test-erofs.sh does, by pointing a
// symlink at a live tmpfs. What is worth pinning here is that the refusal is
// named, since the raw errno for it is a bare "invalid argument".
func TestKernelUnmountRefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "merged")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	err := kernelUnmount(context.Background(), link)
	if err == nil {
		t.Fatal("kernelUnmount followed a symlink")
	}
	if !strings.Contains(err.Error(), "refusing to follow a symlink") {
		t.Errorf("error %q does not name the symlink refusal", err)
	}
}

func TestBuildKernelLayerArgs(t *testing.T) {
	got := buildKernelLayerArgs("/blobs/abc", "/mnt/x")
	want := []string{"mount", "-t", "erofs", "-o", "ro", "/blobs/abc", "/mnt/x"}
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

// Every one of these paths comes from the DEST the user named. ':' is the one
// that can silently compose a wrong stack rather than failing, since overlayfs
// would read a single lowerdir as two.
func TestOverlayArgsEscapeSeparators(t *testing.T) {
	dest := `/mnt/od:d,d\d`
	lowers := []string{dest + "/layers/01", dest + "/layers/00"}
	upper, work, merged := dest+"/upper", dest+"/work", dest+"/merged"
	esc := `/mnt/od\:d\,d\\d`

	kernel := buildKernelOverlayArgs(lowers, upper, work, merged, false)
	wantOpts := "lowerdir=" + esc + `/layers/01:` + esc + `/layers/00` +
		",upperdir=" + esc + "/upper,workdir=" + esc + "/work"
	if kernel[4] != wantOpts {
		t.Errorf("kernel opts:\n got %s\nwant %s", kernel[4], wantOpts)
	}
	// The mountpoint is its own argv element, so it must stay verbatim.
	if kernel[6] != merged {
		t.Errorf("mountpoint: got %s want %s", kernel[6], merged)
	}

	fuse := buildFuseOverlayArgs(lowers, upper, work, merged, false)
	if fuse[2] != wantOpts {
		t.Errorf("fuse opts:\n got %s\nwant %s", fuse[2], wantOpts)
	}
	if fuse[3] != merged {
		t.Errorf("mountpoint: got %s want %s", fuse[3], merged)
	}
}

func TestBuildFusermountUmountArgs(t *testing.T) {
	got := buildFusermountUmountArgs("/usr/bin/fusermount3", "/mnt/x")
	want := []string{"/usr/bin/fusermount3", "-u", "/mnt/x"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
