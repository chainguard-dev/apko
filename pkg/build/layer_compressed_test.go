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
	"fmt"
	"io"
	"math/rand"
	"os"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"

	"chainguard.dev/apko/pkg/options"
)

// buildTestLayer writes a deterministic mixed-compressibility layer of size
// bytes in the requested mode with workers compressor workers, returning the
// layer, the directory holding its files, and the file the writer wrote to.
func buildTestLayer(t *testing.T, compressed bool, compression options.Compression, workers, size int) (v1.Layer, string, string) {
	t.Helper()

	dir := t.TempDir()
	f, err := os.CreateTemp(dir, "layer-*.tar"+compression.Extension())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	lw, err := newLayerWriter(f, compressed, compression, workers)
	if err != nil {
		t.Fatal(err)
	}

	content := make([]byte, size)
	rand.New(rand.NewSource(0x2781)).Read(content[:1<<20]) // 1 MiB incompressible, the rest zeros
	hdr := &tar.Header{Name: "usr/blob", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(content))}
	if err := lw.w.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := lw.w.Write(content); err != nil {
		t.Fatal(err)
	}

	l, err := lw.finalize()
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	return l, dir, f.Name()
}

// gzipFixtureSize spans several pgzip blocks. goldenCompressedDigest depends
// on it.
const gzipFixtureSize = 3 << 20

// zstdFixtureSize spans more than one zstd concurrent-blocks job (32 MiB at
// the default window), which the encoder lays out differently from a serial
// stream.
const zstdFixtureSize = 64 << 20

// goldenCompressedDigest is the gzip digest of buildTestLayer's fixture under
// the current pgzip level and block size. A deliberate change to either is
// expected to update it.
const goldenCompressedDigest = "sha256:8bd4b60ed50be8a11f45c8ec53652e3fca95ad67b9eceb78a6dc371135458b7a"

func TestCompressedLayerEquivalence(t *testing.T) {
	legacy, legacyDir, _ := buildTestLayer(t, false, options.Gzip, 4, gzipFixtureSize)
	single, singleDir, singleFile := buildTestLayer(t, true, options.Gzip, 4, gzipFixtureSize)

	legacyDiff, err := legacy.DiffID()
	if err != nil {
		t.Fatal(err)
	}
	// The legacy Digest call below populates the process-global
	// compressionCache; without this cleanup, a repeat run (-count>1) takes
	// the cache-hit path and never creates the legacy .gz file.
	t.Cleanup(func() { compressionCache.Delete(legacy.(*layer).cacheKey()) })
	singleDiff, err := single.DiffID()
	if err != nil {
		t.Fatal(err)
	}
	if legacyDiff != singleDiff {
		t.Errorf("DiffID: got = %v, want = %v", singleDiff, legacyDiff)
	}

	legacyDigest, err := legacy.Digest() // triggers the legacy second-pass compression
	if err != nil {
		t.Fatal(err)
	}
	singleDigest, err := single.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if legacyDigest != singleDigest {
		t.Errorf("compressed digest: got = %v, want = %v", singleDigest, legacyDigest)
	}
	// Absolute pin alongside the relative check: the fixture is deterministic,
	// so this is what catches a pgzip or block-size change moving every blob
	// digest, which the two modes agreeing with each other never would.
	if singleDigest.String() != goldenCompressedDigest {
		t.Errorf("compressed digest: got = %v, want = %v", singleDigest, goldenCompressedDigest)
	}

	legacySize, err := legacy.Size()
	if err != nil {
		t.Fatal(err)
	}
	singleSize, err := single.Size()
	if err != nil {
		t.Fatal(err)
	}
	if legacySize != singleSize {
		t.Errorf("compressed size: got = %d, want = %d", singleSize, legacySize)
	}

	if got := countFiles(t, singleDir); got != 1 {
		t.Errorf("single-pass files: got = %d, want = 1", got)
	}
	if got := countFiles(t, legacyDir); got != 2 {
		t.Errorf("legacy files: got = %d, want = 2 (plain + gz)", got)
	}

	raw, err := os.ReadFile(singleFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 2 || raw[0] != 0x1f || raw[1] != 0x8b {
		t.Errorf("compressed file does not start with gzip magic: % x", raw[:min(2, len(raw))])
	}

	// Round-trips the compressed layer through gunzip and compares it to the
	// legacy plain tar.
	legacyTar := readAllUncompressed(t, legacy)
	singleTar := readAllUncompressed(t, single)
	if !bytes.Equal(legacyTar, singleTar) {
		t.Errorf("Uncompressed() bytes differ: legacy %d bytes, single-pass %d bytes", len(legacyTar), len(singleTar))
	}
}

// TestCompressedLayerEquivalenceZstd checks that zstd layers written in a
// single pass match ones compressed in a second pass, carry the zstd media
// type, and round-trip back to the same tar. Single-pass multi-layer builds
// use one worker per layer while other paths use pgzipThreads, so the
// single-pass layer is written with both to pin that the bytes do not depend
// on the worker count.
func TestCompressedLayerEquivalenceZstd(t *testing.T) {
	legacy, legacyDir, _ := buildTestLayer(t, false, options.Zstd, pgzipThreads, zstdFixtureSize)
	single, singleDir, singleFile := buildTestLayer(t, true, options.Zstd, 1, zstdFixtureSize)
	singleN, _, _ := buildTestLayer(t, true, options.Zstd, 8, zstdFixtureSize)
	t.Cleanup(func() { compressionCache.Delete(legacy.(*layer).cacheKey()) })

	for _, l := range []v1.Layer{legacy, single, singleN} {
		mt, err := l.MediaType()
		if err != nil {
			t.Fatal(err)
		}
		if mt != v1types.OCILayerZStd {
			t.Errorf("MediaType: got = %v, want = %v", mt, v1types.OCILayerZStd)
		}
	}

	legacyDigest, err := legacy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	singleDigest, err := single.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if legacyDigest != singleDigest {
		t.Errorf("compressed digest: got = %v, want = %v", singleDigest, legacyDigest)
	}
	singleNDigest, err := singleN.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if singleNDigest != singleDigest {
		t.Errorf("compressed digest with 8 workers: got = %v, want = %v (1 worker)", singleNDigest, singleDigest)
	}

	// The gzip fixture has the same diffID, so a shared cache entry would
	// hand back the gzip digest.
	gzipLayer, _, _ := buildTestLayer(t, true, options.Gzip, 4, gzipFixtureSize)
	gzipDigest, err := gzipLayer.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if gzipDigest == singleDigest {
		t.Errorf("zstd digest equals gzip digest %v", gzipDigest)
	}

	if got := countFiles(t, singleDir); got != 1 {
		t.Errorf("single-pass files: got = %d, want = 1", got)
	}
	if got := countFiles(t, legacyDir); got != 2 {
		t.Errorf("legacy files: got = %d, want = 2 (plain + zst)", got)
	}

	raw, err := os.ReadFile(singleFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(raw, []byte{0x28, 0xb5, 0x2f, 0xfd}) {
		t.Errorf("compressed file does not start with zstd magic: % x", raw[:min(4, len(raw))])
	}

	legacyTar := readAllUncompressed(t, legacy)
	singleTar := readAllUncompressed(t, single)
	if !bytes.Equal(legacyTar, singleTar) {
		t.Errorf("Uncompressed() bytes differ: legacy %d bytes, single-pass %d bytes", len(legacyTar), len(singleTar))
	}
}

func readAllUncompressed(t *testing.T, l v1.Layer) []byte {
	t.Helper()
	rc, err := l.Uncompressed()
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if err := rc.Close(); err != nil {
		t.Errorf("Uncompressed().Close(): got = %v, want = nil", err)
	}
	return b
}

func countFiles(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

// TestSinglePassLayerBypassesCompressionCache pins that a single-pass layer
// neither consults nor populates the compression cache. Both modes share one
// struct, so the cache lookup sits one branch away from a layer that has
// nothing to look up, and a regression there would report a cache miss for
// every single-pass layer while still returning the right digest.
func TestSinglePassLayerBypassesCompressionCache(t *testing.T) {
	l, _, _ := buildTestLayer(t, true, options.Gzip, 4, gzipFixtureSize)
	sl, ok := l.(*layer)
	if !ok {
		t.Fatalf("single-pass layer: got %T, want *layer", l)
	}

	// The legacy half of the equivalence test writes the same fixture, so the
	// cache may already hold this diffID from another test in this process.
	compressionCache.Delete(sl.cacheKey())
	t.Cleanup(func() { compressionCache.Delete(sl.cacheKey()) })

	if _, err := l.Digest(); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Size(); err != nil {
		t.Fatal(err)
	}

	if sl.cacheCounted {
		t.Error("cacheCounted = true, want false: a single-pass layer records no cache access")
	}
	if _, ok := compressionCache.Load(sl.cacheKey()); ok {
		t.Error("compressionCache holds an entry for a single-pass layer's diffID")
	}
}

// TestLayerWriterFinalizeTwice pins finalize's second-call behavior, which is
// what lets splitLayers use it as an unconditional teardown: the cleanup path
// runs over every open writer, including ones it already finalized.
func TestLayerWriterFinalizeTwice(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		t.Run(fmt.Sprintf("compressed=%v", compressed), func(t *testing.T) {
			f, err := os.CreateTemp(t.TempDir(), "layer-*.tar.gz")
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()

			lw, err := newLayerWriter(f, compressed, options.Gzip, 2)
			if err != nil {
				t.Fatal(err)
			}
			if err := lw.w.WriteHeader(&tar.Header{Name: "usr/", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
				t.Fatal(err)
			}

			if _, err := lw.finalize(); err != nil {
				t.Fatalf("finalize: %v", err)
			}
			if _, err := lw.finalize(); err == nil {
				t.Error("second finalize: got = nil, want error")
			}
		})
	}
}

// TestImageLayoutToLayer_CompressedLayerFile covers the option-to-writer
// wiring only; equivalence is proven at the writer level above.
func TestImageLayoutToLayer_CompressedLayerFile(t *testing.T) {
	build := func(opts ...Option) string {
		t.Helper()
		bc := &Context{
			o:  options.Options{TempDirPath: t.TempDir(), SourceDateEpoch: epoch},
			fs: seedFS(t),
		}
		for _, o := range opts {
			if err := o(bc); err != nil {
				t.Fatal(err)
			}
		}
		path, _, err := bc.ImageLayoutToLayer(context.Background())
		if err != nil {
			t.Fatalf("ImageLayoutToLayer: %v", err)
		}
		return path
	}

	if got := isGzip(t, build(WithCompressedLayerFile(true))); !got {
		t.Error("enabled: layer file is not gzip")
	}
	if got := isGzip(t, build(WithCompressedLayerFile(false))); got {
		t.Error("disabled: layer file is gzip, want plain tar")
	}
	if got := isGzip(t, build()); got {
		t.Error("option absent: layer file is gzip, want plain tar")
	}
}

func isGzip(t *testing.T, path string) bool {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b
}
