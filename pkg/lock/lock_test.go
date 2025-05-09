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

package lock

import (
	"testing"

	"chainguard.dev/apko/pkg/build/types"
)

func TestArch2LockedPackages(t *testing.T) {
	l := Lock{
		Contents: LockContents{
			Packages: []LockPkg{{
				Name:         "avx",
				Version:      "1.2.3",
				Architecture: "x86_64",
			}, {
				Name:         "sve",
				Version:      "2.3.4",
				Architecture: "aarch64",
			}},
		},
	}

	archs := []types.Architecture{types.Architecture("aarch64")}
	if got, want := len(l.Arch2LockedPackages(archs)), 1; got != want {
		t.Errorf("wanted %d arch, got %d", want, got)
	}
}
