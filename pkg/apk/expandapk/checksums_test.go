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

package expandapk

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"chainguard.dev/apko/internal/sha1cd"
	"chainguard.dev/apko/internal/sha1cd/sha1cdtest"
)

// tarWithFile builds a one-file tar whose entry carries the given SHA-1 in the
// PAX record apk uses for per-file checksums.
func tarWithFile(t *testing.T, content, checksum []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{
		Name:       "usr/share/collide",
		Typeflag:   tar.TypeReg,
		Mode:       0o644,
		Size:       int64(len(content)),
		Format:     tar.FormatPAX,
		PAXRecords: map[string]string{paxRecordsChecksumKey: hex.EncodeToString(checksum)},
	}); err != nil {
		t.Fatalf("writing header: %v", err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatalf("writing content: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("closing tar: %v", err)
	}
	return buf.Bytes()
}

// A file whose content is a known SHA-1 collision must be rejected, even when
// the checksum in its header is the one collision detection produces: the
// digest is untrustworthy, so it cannot be used to accept the file.
func TestCheckSumsRejectsCollision(t *testing.T) {
	collide := sha1cdtest.Shattered(t)

	// The digest sha1cd computes for colliding input, which an attacker would
	// have to put in the header for the comparison to otherwise succeed.
	h := sha1cd.New()
	if _, err := h.Write(collide); err != nil {
		t.Fatal(err)
	}
	mitigated := h.Sum(nil)

	err := checkSums(context.Background(), bytes.NewReader(tarWithFile(t, collide, mitigated)))
	if !errors.Is(err, sha1cd.ErrCollision) {
		t.Errorf("checkSums = %v, want ErrCollision", err)
	}
}

// The same path must still accept an ordinary file, so the check is not simply
// failing everything.
func TestCheckSumsAcceptsMatchingChecksum(t *testing.T) {
	content := []byte("hello world")
	sum, err := sha1cd.SumBytes(content)
	if err != nil {
		t.Fatal(err)
	}

	if err := checkSums(context.Background(), bytes.NewReader(tarWithFile(t, content, sum))); err != nil {
		t.Errorf("checkSums = %v, want nil", err)
	}
}

func TestCheckSumsRejectsMismatchedChecksum(t *testing.T) {
	wrong, err := sha1cd.SumBytes([]byte("not the content"))
	if err != nil {
		t.Fatal(err)
	}

	err = checkSums(context.Background(), bytes.NewReader(tarWithFile(t, []byte("hello world"), wrong)))
	if err == nil {
		t.Error("checkSums = nil, want a checksum mismatch error")
	}
	if errors.Is(err, sha1cd.ErrCollision) {
		t.Errorf("checkSums = %v, want a checksum mismatch rather than a collision", err)
	}
}
