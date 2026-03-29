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
