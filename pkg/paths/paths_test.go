// Copyright 2025 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package paths

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAdvertiseCachedFile(t *testing.T) {
	tmpDir := t.TempDir()
	src1 := tmpDir + "/src1.tmp"
	src2 := tmpDir + "/src2.tmp"
	content := "content"
	if err := os.WriteFile(src1, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src2, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	dst := tmpDir + "/target"
	t.Run("dst does not exists", func(t *testing.T) {
		if err := AdvertiseCachedFile(src1, dst); err != nil {
			t.Fatal(err)
		}
		dstContent, err := os.ReadFile(dst)
		if err != nil {
			t.Fatal(err)
		}
		if string(dstContent) != content {
			t.Fatalf("content mismatch: %s != %s", string(dstContent), content)
		}
	})

	t.Run("dst exists", func(t *testing.T) {
		if err := AdvertiseCachedFile(src2, dst); err != nil {
			t.Fatal(err)
		}
		// check the symlink
		rel1, err := filepath.Rel(filepath.Dir(dst), src1)
		if err != nil {
			t.Fatal(err)
		}
		if l, err := os.Readlink(dst); err != nil {
			t.Fatal(err)
		} else if l != rel1 {
			t.Fatalf("symlink should stay in tact: %s != %s", l, src2)
		}

		// check that src2 is removed
		if _, err := os.Stat(src2); !os.IsNotExist(err) {
			t.Fatalf("src2 should be removed: %v", err)
		}
	})
}
