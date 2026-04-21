package apk

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
)

func TestPathTraversal(t *testing.T) {
	ctx := context.Background()

	sandbox := t.TempDir()
	base := filepath.Join(sandbox, "base")
	outsideDir := filepath.Join(sandbox, "outside", "pwned")
	outsideLink := filepath.Join(sandbox, "outside", "pwned-link")

	fsys := apkfs.DirFS(ctx, base, apkfs.WithCreateDir())
	if fsys == nil {
		t.Fatalf("failed to create dirfs for base %s", base)
	}

	a, err := New(ctx, WithFS(fsys))
	if err != nil {
		t.Fatalf("apk.New: %v", err)
	}

	dirName := filepath.ToSlash(filepath.Join("..", "outside", "pwned"))
	symlinkName := filepath.ToSlash(filepath.Join("..", "outside", "pwned-link"))
	r, err := makeTestTar(dirName, symlinkName, "target")
	if err != nil {
		t.Fatalf("makeTestTar: %v", err)
	}

	_, err = a.installAPKFiles(ctx, r, &Package{})
	if err == nil {
		t.Fatalf("expected installAPKFiles to fail after fix, but it succeeded")
	}

	if _, statErr := os.Stat(outsideDir); statErr == nil {
		t.Fatalf("expected %s to not exist after fix", outsideDir)
	}
	if _, statErr := os.Lstat(outsideLink); statErr == nil {
		t.Fatalf("expected %s to not exist after fix", outsideLink)
	}
}

func TestPathTraversalHardlink(t *testing.T) {
	ctx := context.Background()

	sandbox := t.TempDir()
	base := filepath.Join(sandbox, "base")
	outsideHardlink := filepath.Join(sandbox, "outside", "pwned-hardlink")

	fsys := apkfs.DirFS(ctx, base, apkfs.WithCreateDir())
	if fsys == nil {
		t.Fatalf("failed to create dirfs for base %s", base)
	}

	a, err := New(ctx, WithFS(fsys))
	if err != nil {
		t.Fatalf("apk.New: %v", err)
	}

	// Create a tar with:
	// 1. A regular file inside the base (the hardlink target)
	// 2. A hardlink with traversal path pointing to that file
	r, err := makeTestTarWithHardlink(
		"legitimate-file",
		filepath.ToSlash(filepath.Join("..", "outside", "pwned-hardlink")),
		"legitimate-file",
	)
	if err != nil {
		t.Fatalf("makeTestTarWithHardlink: %v", err)
	}

	_, err = a.installAPKFiles(ctx, r, &Package{})
	if err == nil {
		t.Fatalf("expected installAPKFiles to fail after fix, but it succeeded")
	}

	if _, statErr := os.Lstat(outsideHardlink); statErr == nil {
		t.Fatalf("expected %s to not exist after fix", outsideHardlink)
	}
}

// TestSymlinkEscape_FileThroughAbsoluteSymlink covers the classic symlink-escape
// shape: a malicious APK plants a symlink inside the image whose target is an
// absolute path pointing outside the rootfs, then a regular file whose tar
// header name traverses that symlink. The install must fail and the outside
// path must remain untouched.
func TestSymlinkEscape_FileThroughAbsoluteSymlink(t *testing.T) {
	ctx := t.Context()

	sandbox := t.TempDir()
	base := filepath.Join(sandbox, "base")
	outsideDir := filepath.Join(sandbox, "outside")
	outsideFile := filepath.Join(outsideDir, "pwned")
	if err := os.MkdirAll(outsideDir, 0o755); err != nil {
		t.Fatal(err)
	}

	fsys := apkfs.DirFS(ctx, base, apkfs.WithCreateDir())
	if fsys == nil {
		t.Fatalf("failed to create dirfs for base %s", base)
	}

	a, err := New(ctx, WithFS(fsys))
	if err != nil {
		t.Fatalf("apk.New: %v", err)
	}

	r, err := makeSymlinkThenFileTar("evil", outsideDir, "evil/pwned", []byte("malicious"))
	if err != nil {
		t.Fatalf("makeSymlinkThenFileTar: %v", err)
	}

	if _, err := a.installAPKFiles(ctx, r, &Package{}); err == nil {
		t.Fatalf("expected installAPKFiles to fail, but it succeeded")
	}

	if _, statErr := os.Stat(outsideFile); statErr == nil {
		t.Fatalf("expected %s to not exist after fix", outsideFile)
	}
}

// TestSymlinkEscape_FileThroughRelativeSymlink is the ../outside variant.
func TestSymlinkEscape_FileThroughRelativeSymlink(t *testing.T) {
	ctx := t.Context()

	sandbox := t.TempDir()
	base := filepath.Join(sandbox, "base")
	outsideDir := filepath.Join(sandbox, "outside")
	outsideFile := filepath.Join(outsideDir, "pwned")
	if err := os.MkdirAll(outsideDir, 0o755); err != nil {
		t.Fatal(err)
	}

	fsys := apkfs.DirFS(ctx, base, apkfs.WithCreateDir())
	if fsys == nil {
		t.Fatalf("failed to create dirfs for base %s", base)
	}

	a, err := New(ctx, WithFS(fsys))
	if err != nil {
		t.Fatalf("apk.New: %v", err)
	}

	r, err := makeSymlinkThenFileTar("evil", "../outside", "evil/pwned", []byte("malicious"))
	if err != nil {
		t.Fatalf("makeSymlinkThenFileTar: %v", err)
	}

	if _, err := a.installAPKFiles(ctx, r, &Package{}); err == nil {
		t.Fatalf("expected installAPKFiles to fail, but it succeeded")
	}

	if _, statErr := os.Stat(outsideFile); statErr == nil {
		t.Fatalf("expected %s to not exist after fix", outsideFile)
	}
}

// TestSymlinkEscape_MkdirAllThroughSymlink plants a symlink whose target is an
// outside directory, then a TypeDir entry traversing the symlink. MkdirAll
// must not merge new dirs into the outside location.
func TestSymlinkEscape_MkdirAllThroughSymlink(t *testing.T) {
	ctx := t.Context()

	sandbox := t.TempDir()
	base := filepath.Join(sandbox, "base")
	outsideDir := filepath.Join(sandbox, "outside")
	outsideSub := filepath.Join(outsideDir, "sub")
	if err := os.MkdirAll(outsideDir, 0o755); err != nil {
		t.Fatal(err)
	}

	fsys := apkfs.DirFS(ctx, base, apkfs.WithCreateDir())
	if fsys == nil {
		t.Fatalf("failed to create dirfs for base %s", base)
	}

	a, err := New(ctx, WithFS(fsys))
	if err != nil {
		t.Fatalf("apk.New: %v", err)
	}

	r, err := makeSymlinkThenDirTar("evil", outsideDir, "evil/sub")
	if err != nil {
		t.Fatalf("makeSymlinkThenDirTar: %v", err)
	}

	if _, err := a.installAPKFiles(ctx, r, &Package{}); err == nil {
		t.Fatalf("expected installAPKFiles to fail, but it succeeded")
	}

	if _, statErr := os.Stat(outsideSub); statErr == nil {
		t.Fatalf("expected %s to not exist after fix", outsideSub)
	}
}

// TestSymlinkEscape_HardlinkThroughSymlink validates the hardlink path: the
// prior GHSA guarded target-side escapes, but the newname side could still be
// redirected through an attacker-planted symlink.
func TestSymlinkEscape_HardlinkThroughSymlink(t *testing.T) {
	ctx := t.Context()

	sandbox := t.TempDir()
	base := filepath.Join(sandbox, "base")
	outsideDir := filepath.Join(sandbox, "outside")
	outsideLinked := filepath.Join(outsideDir, "linked")
	if err := os.MkdirAll(outsideDir, 0o755); err != nil {
		t.Fatal(err)
	}

	fsys := apkfs.DirFS(ctx, base, apkfs.WithCreateDir())
	if fsys == nil {
		t.Fatalf("failed to create dirfs for base %s", base)
	}

	a, err := New(ctx, WithFS(fsys))
	if err != nil {
		t.Fatalf("apk.New: %v", err)
	}

	r, err := makeHardlinkThroughSymlinkTar("legit", "evil", outsideDir, "evil/linked")
	if err != nil {
		t.Fatalf("makeHardlinkThroughSymlinkTar: %v", err)
	}

	if _, err := a.installAPKFiles(ctx, r, &Package{}); err == nil {
		t.Fatalf("expected installAPKFiles to fail, but it succeeded")
	}

	if _, statErr := os.Lstat(outsideLinked); statErr == nil {
		t.Fatalf("expected %s to not exist after fix", outsideLinked)
	}
}

func makeSymlinkThenFileTar(symlinkName, symlinkTarget, fileName string, content []byte) (*bytes.Reader, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	if err := tw.WriteHeader(&tar.Header{
		Name:     symlinkName,
		Linkname: symlinkTarget,
		Typeflag: tar.TypeSymlink,
		Mode:     0o777,
	}); err != nil {
		return nil, err
	}

	if err := tw.WriteHeader(&tar.Header{
		Name:     fileName,
		Typeflag: tar.TypeReg,
		Mode:     0o644,
		Size:     int64(len(content)),
	}); err != nil {
		return nil, err
	}
	if _, err := tw.Write(content); err != nil {
		return nil, err
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}
	return bytes.NewReader(buf.Bytes()), nil
}

func makeSymlinkThenDirTar(symlinkName, symlinkTarget, dirName string) (*bytes.Reader, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	if err := tw.WriteHeader(&tar.Header{
		Name:     symlinkName,
		Linkname: symlinkTarget,
		Typeflag: tar.TypeSymlink,
		Mode:     0o777,
	}); err != nil {
		return nil, err
	}

	if err := tw.WriteHeader(&tar.Header{
		Name:     dirName,
		Typeflag: tar.TypeDir,
		Mode:     0o755,
	}); err != nil {
		return nil, err
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}
	return bytes.NewReader(buf.Bytes()), nil
}

func makeHardlinkThroughSymlinkTar(regularName, symlinkName, symlinkTarget, hardlinkName string) (*bytes.Reader, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	content := []byte("legitimate")
	if err := tw.WriteHeader(&tar.Header{
		Name:     regularName,
		Typeflag: tar.TypeReg,
		Mode:     0o644,
		Size:     int64(len(content)),
	}); err != nil {
		return nil, err
	}
	if _, err := tw.Write(content); err != nil {
		return nil, err
	}

	if err := tw.WriteHeader(&tar.Header{
		Name:     symlinkName,
		Linkname: symlinkTarget,
		Typeflag: tar.TypeSymlink,
		Mode:     0o777,
	}); err != nil {
		return nil, err
	}

	if err := tw.WriteHeader(&tar.Header{
		Name:     hardlinkName,
		Linkname: regularName,
		Typeflag: tar.TypeLink,
		Mode:     0o644,
	}); err != nil {
		return nil, err
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}
	return bytes.NewReader(buf.Bytes()), nil
}

func makeTestTar(dirName, symlinkName, symlinkTarget string) (*bytes.Reader, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	hdr := &tar.Header{
		Name:     dirName,
		Typeflag: tar.TypeDir,
		Mode:     0o755,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return nil, err
	}

	hdr = &tar.Header{
		Name:     symlinkName,
		Linkname: symlinkTarget,
		Typeflag: tar.TypeSymlink,
		Mode:     0o777,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return nil, err
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}
	return bytes.NewReader(buf.Bytes()), nil
}

func makeTestTarWithHardlink(fileName, hardlinkName, hardlinkTarget string) (*bytes.Reader, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	// First create a regular file (the hardlink target)
	content := []byte("test content")
	hdr := &tar.Header{
		Name:     fileName,
		Typeflag: tar.TypeReg,
		Mode:     0o644,
		Size:     int64(len(content)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return nil, err
	}
	if _, err := tw.Write(content); err != nil {
		return nil, err
	}

	// Then create a hardlink with traversal path
	hdr = &tar.Header{
		Name:     hardlinkName,
		Linkname: hardlinkTarget,
		Typeflag: tar.TypeLink,
		Mode:     0o644,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return nil, err
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}
	return bytes.NewReader(buf.Bytes()), nil
}
