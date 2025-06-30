// Copyright 2025 Chainguard, Inc.
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
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/require"
)

func TestLayerCompressionCache(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := t.TempDir()

	// Create test content
	testContent := []byte("test layer content for compression cache")

	// Calculate the diffID (hash of uncompressed content)
	h := sha256.Sum256(testContent)
	diffID := v1.Hash{
		Algorithm: "sha256",
		Hex:       hex.EncodeToString(h[:]),
	}

	// Create first layer with test content
	file1 := filepath.Join(tmpDir, "layer1.tar")
	err := os.WriteFile(file1, testContent, 0644)
	require.NoError(t, err)

	layer1 := &layer{
		uncompressed: file1,
		diffid:       &diffID,
		desc: &v1.Descriptor{
			MediaType: v1types.OCILayer,
		},
	}

	// Get digest for first layer - this should compress the layer
	digest1, err := layer1.Digest()
	require.NoError(t, err)
	require.NotEmpty(t, digest1.String())

	// Verify the compressed file was created
	require.FileExists(t, file1+".gz")

	// Get size for first layer - should use cached values
	size1, err := layer1.Size()
	require.NoError(t, err)
	require.Greater(t, size1, int64(0))

	// Create second layer with identical content (same diffID)
	file2 := filepath.Join(tmpDir, "layer2.tar")
	err = os.WriteFile(file2, testContent, 0644)
	require.NoError(t, err)

	layer2 := &layer{
		uncompressed: file2,
		diffid:       &diffID, // Same diffID as layer1
		desc: &v1.Descriptor{
			MediaType: v1types.OCILayer,
		},
	}

	// Get digest for second layer - should use cached descriptor
	digest2, err := layer2.Digest()
	require.NoError(t, err)
	require.Equal(t, digest1, digest2, "Cached digest should match")

	// Get size for second layer - should use cached descriptor
	size2, err := layer2.Size()
	require.NoError(t, err)
	require.Equal(t, size1, size2, "Cached size should match")

	// Verify that layer2's descriptor was populated from cache
	require.Equal(t, layer1.desc.Digest, layer2.desc.Digest)
	require.Equal(t, layer1.desc.Size, layer2.desc.Size)

	// The compressed file for layer2 should NOT exist yet since we only used cached values
	require.NoFileExists(t, file2+".gz")

	// Now actually compress layer2 by calling Compressed()
	rc, err := layer2.Compressed()
	require.NoError(t, err)
	rc.Close()

	// Now the compressed file should exist
	require.FileExists(t, file2+".gz")

	// Create third layer with different content
	differentContent := []byte("different content that will have different diffID")
	h3 := sha256.Sum256(differentContent)
	diffID3 := v1.Hash{
		Algorithm: "sha256",
		Hex:       hex.EncodeToString(h3[:]),
	}

	file3 := filepath.Join(tmpDir, "layer3.tar")
	err = os.WriteFile(file3, differentContent, 0644)
	require.NoError(t, err)

	layer3 := &layer{
		uncompressed: file3,
		diffid:       &diffID3,
		desc: &v1.Descriptor{
			MediaType: v1types.OCILayer,
		},
	}

	// Get digest for third layer - should NOT use cache (different diffID)
	digest3, err := layer3.Digest()
	require.NoError(t, err)
	require.NotEqual(t, digest1, digest3, "Different content should have different digest")

	// Verify the compressed file was created for layer3
	require.FileExists(t, file3+".gz")
}

func TestLayerCompressionCacheConsistency(t *testing.T) {
	// This test verifies that the cache returns consistent results
	tmpDir := t.TempDir()

	// Create test content
	testContent := []byte("consistency test content")
	h := sha256.Sum256(testContent)
	diffID := v1.Hash{
		Algorithm: "sha256",
		Hex:       hex.EncodeToString(h[:]),
	}

	// Create and compress first layer
	file1 := filepath.Join(tmpDir, "consistent1.tar")
	err := os.WriteFile(file1, testContent, 0644)
	require.NoError(t, err)

	layer1 := &layer{
		uncompressed: file1,
		diffid:       &diffID,
		desc: &v1.Descriptor{
			MediaType: v1types.OCILayer,
		},
	}

	// Compress the layer
	err = layer1.compress()
	require.NoError(t, err)

	originalDigest := layer1.desc.Digest
	originalSize := layer1.desc.Size

	// Create multiple layers with same diffID and verify they all get same cached values
	for i := 2; i <= 5; i++ {
		file := filepath.Join(tmpDir, "consistent"+strconv.Itoa(i)+".tar")
		err := os.WriteFile(file, testContent, 0644)
		require.NoError(t, err)

		layer := &layer{
			uncompressed: file,
			diffid:       &diffID,
			desc: &v1.Descriptor{
				MediaType: v1types.OCILayer,
			},
		}

		// Check digest uses cache
		digest, err := layer.Digest()
		require.NoError(t, err)
		require.Equal(t, originalDigest, digest, "Cached digest should be consistent across all layers")

		// Check size uses cache
		size, err := layer.Size()
		require.NoError(t, err)
		require.Equal(t, originalSize, size, "Cached size should be consistent across all layers")
	}
}

func TestLayerUncompressedAccess(t *testing.T) {
	// Test that we can still access uncompressed content
	tmpDir := t.TempDir()

	testContent := []byte("uncompressed access test")
	h := sha256.Sum256(testContent)
	diffID := v1.Hash{
		Algorithm: "sha256",
		Hex:       hex.EncodeToString(h[:]),
	}

	file := filepath.Join(tmpDir, "uncompressed.tar")
	err := os.WriteFile(file, testContent, 0644)
	require.NoError(t, err)

	layer := &layer{
		uncompressed: file,
		diffid:       &diffID,
		desc: &v1.Descriptor{
			MediaType: v1types.OCILayer,
		},
	}

	// Access uncompressed content
	rc, err := layer.Uncompressed()
	require.NoError(t, err)
	defer rc.Close()

	content, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.Equal(t, testContent, content)

	// Verify DiffID
	gotDiffID, err := layer.DiffID()
	require.NoError(t, err)
	require.Equal(t, diffID, gotDiffID)
}
