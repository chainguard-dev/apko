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

package build

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	erofs "github.com/erofs/go-erofs"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/options"
)

// epoch is a fixed timestamp used by reproducibility-sensitive tests so the
// recorded mtime never depends on wall-clock state.
var epoch = time.Unix(1700000000, 0).UTC()

func seedFS(t *testing.T) apkfs.FullFS {
	t.Helper()
	m := apkfs.NewMemFS()
	require.NoError(t, m.MkdirAll("a", 0o755))
	require.NoError(t, m.WriteFile("a/b", []byte("hello world"), 0o644))
	require.NoError(t, m.Symlink("b", "a/link"))
	require.NoError(t, m.SetXattr("a", "user.dir", []byte("foo")))
	require.NoError(t, m.SetXattr("a/b", "user.file", []byte("bar")))
	// stamp known mtimes so the image is reproducible
	require.NoError(t, m.Chtimes("a", epoch, epoch))
	require.NoError(t, m.Chtimes("a/b", epoch, epoch))
	return m
}

func TestWriteErofs_Roundtrip(t *testing.T) {
	m := seedFS(t)

	out := filepath.Join(t.TempDir(), "image.erofs")
	f, err := os.Create(out)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	require.NoError(t, writeErofs(context.Background(), f, m, epoch))
	require.NoError(t, f.Close())

	r, err := os.Open(out)
	require.NoError(t, err)
	defer r.Close()

	img, err := erofs.Open(r)
	require.NoError(t, err)

	// Walk the resulting image and collect what's in it.
	got := map[string]fs.FileInfo{}
	require.NoError(t, fs.WalkDir(img, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		got[path] = info
		return nil
	}))

	require.Contains(t, got, "a", "directory %q missing from image", "a")
	require.Contains(t, got, "a/b", "file %q missing from image", "a/b")
	require.Contains(t, got, "a/link", "symlink %q missing from image", "a/link")

	// File content
	data, err := fs.ReadFile(img, "a/b")
	require.NoError(t, err)
	require.Equal(t, "hello world", string(data))

	// Xattrs (via the accessor interface advertised by erofs.Stat)
	dirX, ok := got["a"].Sys().(*erofs.Stat)
	require.True(t, ok, "expected *erofs.Stat on dir Sys()")
	require.Equal(t, "foo", dirX.Xattrs["user.dir"])

	fileX := got["a/b"].Sys().(*erofs.Stat)
	require.Equal(t, "bar", fileX.Xattrs["user.file"])

	// Symlink target — readable via the image's ReadLink method.
	rl, ok := img.(interface {
		ReadLink(string) (string, error)
	})
	require.True(t, ok, "image does not implement ReadLink")
	target, err := rl.ReadLink("a/link")
	require.NoError(t, err)
	require.Equal(t, "b", target)
}

// TestWriteErofs_SpecialModeBits checks that setuid, setgid and sticky survive
// the write. Go keeps them outside the low 9 bits, so anything that reduces a
// mode with fs.FileMode.Perm() drops them and ships a broken sudo/passwd and a
// world-writable /tmp. Also covers a devnode and a symlink, whose type bits the
// mode fixup must not disturb.
func TestWriteErofs_SpecialModeBits(t *testing.T) {
	m := apkfs.NewMemFS()
	require.NoError(t, m.MkdirAll("usr/bin", 0o755))
	require.NoError(t, m.WriteFile("usr/bin/sudo", []byte("setuid"), fs.ModeSetuid|0o755))
	require.NoError(t, m.WriteFile("usr/bin/unix_chkpwd", []byte("setgid"), fs.ModeSetgid|0o755))
	require.NoError(t, m.WriteFile("usr/bin/both", []byte("both"), fs.ModeSetuid|fs.ModeSetgid|0o755))
	require.NoError(t, m.MkdirAll("tmp", 0o777))
	require.NoError(t, m.Chmod("tmp", fs.ModeSticky|0o777))
	require.NoError(t, m.MkdirAll("dev", 0o755))
	require.NoError(t, m.Mknod("dev/null", unix.S_IFCHR|0o666, int(unix.Mkdev(1, 3))))
	require.NoError(t, m.Symlink("sudo", "usr/bin/sudo-link"))

	out := filepath.Join(t.TempDir(), "image.erofs")
	f, err := os.Create(out)
	require.NoError(t, err)
	require.NoError(t, writeErofs(context.Background(), f, m, epoch))
	require.NoError(t, f.Close())

	r, err := os.Open(out)
	require.NoError(t, err)
	defer r.Close()
	img, err := erofs.Open(r)
	require.NoError(t, err)

	// Lstat so the symlink case reports the link itself. fs.FileInfo.Mode()
	// from the reader carries raw EROFS bits; Stat.Mode is the translated
	// fs.FileMode, so assert against that.
	lstat, ok := img.(interface {
		Lstat(string) (fs.FileInfo, error)
	})
	require.True(t, ok, "image does not implement Lstat")
	statOf := func(path string) *erofs.Stat {
		t.Helper()
		info, err := lstat.Lstat(path)
		require.NoError(t, err)
		st, ok := info.Sys().(*erofs.Stat)
		require.True(t, ok, "expected *erofs.Stat on %s Sys()", path)
		return st
	}

	for _, tc := range []struct {
		path string
		want fs.FileMode
	}{
		{"usr/bin/sudo", fs.ModeSetuid | 0o755},
		{"usr/bin/unix_chkpwd", fs.ModeSetgid | 0o755},
		{"usr/bin/both", fs.ModeSetuid | fs.ModeSetgid | 0o755},
		{"tmp", fs.ModeDir | fs.ModeSticky | 0o777},
	} {
		require.Equal(t, tc.want, statOf(tc.path).Mode, "mode mismatch for %s", tc.path)
	}

	// Devnode: type, permissions and rdev all intact.
	dev := statOf("dev/null")
	require.NotZero(t, dev.Mode&fs.ModeCharDevice, "dev/null lost its char-device type")
	require.Equal(t, fs.FileMode(0o666), dev.Mode.Perm())
	require.Equal(t, unix.Mkdev(1, 3), uint64(dev.Rdev))

	// Symlinks keep EROFS's fixed 0777 and stay symlinks.
	link := statOf("usr/bin/sudo-link")
	require.NotZero(t, link.Mode&fs.ModeSymlink, "sudo-link is not a symlink")
	require.Equal(t, fs.FileMode(0o777), link.Mode.Perm())

	if fsckBin := optionalFsckErofs(t); fsckBin != "" {
		cmd := exec.Command(fsckBin, "-d3", out)
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "fsck.erofs reported a malformed image:\n%s", output)
	}
}

// TestWriteErofs_Xattrs covers extended attributes, file capabilities in
// particular: melange's guest init untars its rootfs with
// --xattrs-include='security.capability', so an EROFS rootfs that dropped
// them would regress silently. Every xattr must reach the image byte-for-byte
// and match what the tar writer records for the same source tree.
func TestWriteErofs_Xattrs(t *testing.T) {
	// A real VFS_CAP_REVISION_2 payload: CAP_NET_RAW, effective.
	caps := []byte{
		0x01, 0x00, 0x00, 0x02, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	want := map[string]map[string]string{
		"usr/bin/ping": {
			// Distinct EROFS name-index prefixes: security., trusted., user.
			"security.capability": string(caps),
			"trusted.origin":      "apko",
			"user.note":           "hello",
		},
		"usr/bin": {"security.selinux": "system_u:object_r:bin_t:s0"},
	}

	m := apkfs.NewMemFS()
	require.NoError(t, m.MkdirAll("usr/bin", 0o755))
	require.NoError(t, m.WriteFile("usr/bin/ping", []byte("ping"), 0o755))
	for path, xattrs := range want {
		for name, value := range xattrs {
			require.NoError(t, m.SetXattr(path, name, []byte(value)))
		}
	}

	out := filepath.Join(t.TempDir(), "image.erofs")
	f, err := os.Create(out)
	require.NoError(t, err)
	require.NoError(t, writeErofs(context.Background(), f, m, epoch))
	require.NoError(t, f.Close())

	r, err := os.Open(out)
	require.NoError(t, err)
	defer r.Close()
	img, err := erofs.Open(r)
	require.NoError(t, err)

	for path, xattrs := range want {
		info, err := fs.Stat(img, path)
		require.NoError(t, err)
		st, ok := info.Sys().(*erofs.Stat)
		require.True(t, ok, "expected *erofs.Stat on %s Sys()", path)
		require.Equal(t, xattrs, st.Xattrs, "xattrs differ for %s", path)
	}

	// Parity with the tar writer over the same source tree: whatever a tar
	// layer would carry as SCHILY.xattr.* records, the EROFS layer must too.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	require.NoError(t, writeTar(context.Background(), tw, m))
	require.NoError(t, tw.Close())

	tr := tar.NewReader(&buf)
	seen := 0
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		path := strings.TrimSuffix(strings.TrimPrefix(hdr.Name, "./"), "/")
		xattrs, ok := want[path]
		if !ok {
			continue
		}
		seen++
		fromTar := map[string]string{}
		for k, v := range hdr.PAXRecords {
			if name, ok := strings.CutPrefix(k, "SCHILY.xattr."); ok {
				fromTar[name] = v
			}
		}
		require.Equal(t, xattrs, fromTar, "tar layer xattrs differ for %s", path)
	}
	require.Equal(t, len(want), seen, "not every path under test appeared in the tar layer")

	// erofs-utils must also accept the xattr encoding. Extraction can't apply
	// security.*/trusted.* as a normal user, so this is a validity check; the
	// read-back above is what verifies the values.
	if fsckBin := optionalFsckErofs(t); fsckBin != "" {
		output, err := exec.Command(fsckBin, "-d3", out).CombinedOutput()
		require.NoError(t, err, "fsck.erofs rejected the image:\n%s", output)
	}
}

// TestImageLayoutToLayer_Erofs exercises ImageLayoutToLayer end-to-end via a
// hand-rolled Context. It confirms the layer returned advertises the erofs
// media type and that DiffID == Digest (raw EROFS has no compression step).
func TestImageLayoutToLayer_Erofs(t *testing.T) {
	m := seedFS(t)
	// checkPaths warns about missing /etc/passwd, /etc/group, /etc/os-release;
	// satisfy those so we get clean test logs.
	require.NoError(t, m.MkdirAll("etc", 0o755))
	require.NoError(t, m.WriteFile("etc/passwd", []byte("root:x:0:0:root:/root:/bin/sh\n"), 0o644))
	require.NoError(t, m.WriteFile("etc/group", []byte("root:x:0:root\n"), 0o644))
	require.NoError(t, m.WriteFile("etc/os-release", []byte("ID=test\n"), 0o644))

	tmp := t.TempDir()
	bc := &Context{
		ic: types.ImageConfiguration{Format: types.LayerFormatErofs},
		o: options.Options{
			TempDirPath:     tmp,
			SourceDateEpoch: epoch,
		},
		fs: m,
	}

	path, layer, err := bc.ImageLayoutToLayer(context.Background())
	require.NoError(t, err)

	mt, err := layer.MediaType()
	require.NoError(t, err)
	require.Equal(t, v1types.MediaType("application/vnd.erofs"), mt)

	digest, err := layer.Digest()
	require.NoError(t, err)
	diffID, err := layer.DiffID()
	require.NoError(t, err)
	require.Equal(t, digest, diffID, "raw EROFS: Digest must equal DiffID")

	// Confirm the on-disk artifact really is an EROFS image.
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	_, err = erofs.Open(f)
	require.NoError(t, err)
}

// TestWriteErofs_FsckErofs validates a generated image with the C reference
// tool from erofs-utils. The test is skipped when fsck.erofs is not on PATH so
// contributors without erofs-utils installed still get a green build. CI
// images that include erofs-utils will actually exercise this path.
func TestWriteErofs_FsckErofs(t *testing.T) {
	fsckBin, err := exec.LookPath("fsck.erofs")
	if err != nil {
		t.Skip("fsck.erofs not found in PATH; install erofs-utils to run this test")
	}

	m := seedFS(t)
	out := filepath.Join(t.TempDir(), "image.erofs")
	f, err := os.Create(out)
	require.NoError(t, err)
	require.NoError(t, writeErofs(context.Background(), f, m, epoch))
	require.NoError(t, f.Close())

	// Plain integrity check: superblock CRC, layout, all reachable inodes.
	cmd := exec.Command(fsckBin, "-d3", out)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "fsck.erofs reported a malformed image:\n%s", output)

	// Full content extraction. This walks every inode, decompresses any data,
	// and writes files to disk — a stronger signal than the integrity check
	// alone.
	//
	// Only flags the erofs-utils in Debian/Ubuntu understands are used here.
	// --xattrs, for one, is not universal: the version Ubuntu ships rejects it
	// outright, which broke this test the moment CI first installed the package.
	// Nothing below asserts on xattrs anyway; TestWriteErofs_Xattrs covers them
	// by reading the image back with go-erofs.
	extractDir := t.TempDir()
	cmd = exec.Command(fsckBin, "--extract="+extractDir, "--force", out)
	output, err = cmd.CombinedOutput()
	require.NoError(t, err, "fsck.erofs --extract failed:\n%s", output)

	// Sanity-check the extracted content actually matches what we put in.
	data, err := os.ReadFile(filepath.Join(extractDir, "a", "b"))
	require.NoError(t, err)
	require.Equal(t, "hello world", string(data))

	target, err := os.Readlink(filepath.Join(extractDir, "a", "link"))
	require.NoError(t, err)
	require.Equal(t, "b", target)
}

// optionalFsckErofs returns the path to fsck.erofs, or "" when erofs-utils is
// not installed. It is deliberately optional: every caller has already parsed
// the image with go-erofs, so fsck is a second opinion from the C reference
// implementation rather than the only check, and contributors without
// erofs-utils still get a green build. The log line keeps the reduced coverage
// visible in test output instead of silently passing.
//
// Tests whose entire point is the erofs-utils cross-check skip explicitly
// instead — see TestWriteErofs_FsckErofs.
func optionalFsckErofs(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("fsck.erofs")
	if err != nil {
		t.Log("fsck.erofs not on PATH; skipping the erofs-utils cross-check (go-erofs validation still runs)")
		return ""
	}
	return bin
}

func TestWriteErofs_Reproducible(t *testing.T) {
	build := func(path string) []byte {
		m := seedFS(t)
		f, err := os.Create(path)
		require.NoError(t, err)
		require.NoError(t, writeErofs(context.Background(), f, m, epoch))
		require.NoError(t, f.Close())
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		return data
	}

	tmp := t.TempDir()
	a := build(filepath.Join(tmp, "a.erofs"))
	b := build(filepath.Join(tmp, "b.erofs"))
	require.Equal(t, len(a), len(b), "image sizes differ between identical builds")
	require.True(t, bytes.Equal(a, b), "two identical builds produced byte-different images")
}

// A zero buildTime must still be deterministic. go-erofs stamps
// time.Now().Unix() into the superblock when WithBuildTime is absent, so
// omitting the option for a zero timestamp -- which apko's CLI never produces
// but a library caller easily can -- silently made the digest depend on the
// wall clock.
//
// Asserting that two zero-time builds match would not catch that: the default
// has one-second granularity, so back-to-back builds would agree anyway.
// Instead pin the zero case to the epoch case, which is what the clamp in
// erofsBuildTime promises and what a wall-clock stamp could not produce.
func TestWriteErofs_ZeroBuildTimeIsEpoch(t *testing.T) {
	build := func(path string, bt time.Time) []byte {
		m := seedFS(t)
		f, err := os.Create(path)
		require.NoError(t, err)
		require.NoError(t, writeErofs(context.Background(), f, m, bt))
		require.NoError(t, f.Close())
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		return data
	}

	tmp := t.TempDir()
	zero := build(filepath.Join(tmp, "zero.erofs"), time.Time{})
	epochBuild := build(filepath.Join(tmp, "epoch.erofs"), time.Unix(0, 0))
	require.True(t, bytes.Equal(zero, epochBuild),
		"a zero buildTime must produce the same image as an explicit epoch, not a wall-clock stamp")
}

func TestErofsBuildTime(t *testing.T) {
	for _, tc := range []struct {
		name     string
		in       time.Time
		wantSec  uint64
		wantNsec uint32
	}{
		{"zero clamps to epoch", time.Time{}, 0, 0},
		{"pre-epoch clamps to epoch", time.Unix(-1, 0), 0, 0},
		{"epoch", time.Unix(0, 0), 0, 0},
		{"normal", time.Unix(1700000000, 1234), 1700000000, 1234},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sec, nsec := erofsBuildTime(tc.in)
			require.Equal(t, tc.wantSec, sec)
			require.Equal(t, tc.wantNsec, nsec)
		})
	}
}
