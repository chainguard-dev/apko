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

	"github.com/google/go-cmp/cmp"

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

	archs := []types.Architecture{types.ParseArchitecture("arm64")}
	if got, want := len(l.Arch2LockedPackages(archs)), 1; got != want {
		t.Errorf("wanted %d arch, got %d", want, got)
	}
}

func TestArchitectureCoverage(t *testing.T) {
	archs := func(in ...string) []types.Architecture {
		out := make([]types.Architecture, 0, len(in))
		for _, s := range in {
			out = append(out, types.Architecture(s))
		}
		return out
	}
	pkgs := func(in ...string) []LockPkg {
		out := make([]LockPkg, 0, len(in))
		for _, arch := range in {
			out = append(out, LockPkg{Name: "pkg", Version: "1.2.3", Architecture: arch})
		}
		return out
	}
	repos := func(in ...string) []LockRepo {
		out := make([]LockRepo, 0, len(in))
		for _, arch := range in {
			out = append(out, LockRepo{Name: "repo/" + arch, Architecture: arch})
		}
		return out
	}

	tests := []struct {
		name        string
		contents    LockContents
		requested   []types.Architecture
		wantLocked  []types.Architecture
		wantMissing []types.Architecture
	}{{
		name:        "requested architecture was never locked",
		contents:    LockContents{Packages: pkgs("x86_64"), Repositories: repos("x86_64")},
		requested:   archs("amd64", "arm64"),
		wantLocked:  archs("amd64"),
		wantMissing: archs("arm64"),
	}, {
		name:        "no requested architecture was locked",
		contents:    LockContents{Packages: pkgs("x86_64"), Repositories: repos("x86_64")},
		requested:   archs("arm64", "riscv64"),
		wantLocked:  archs("amd64"),
		wantMissing: archs("arm64", "riscv64"),
	}, {
		name:       "lock covers exactly the requested architectures",
		contents:   LockContents{Packages: pkgs("x86_64", "aarch64"), Repositories: repos("x86_64", "aarch64")},
		requested:  archs("amd64", "arm64"),
		wantLocked: archs("amd64", "arm64"),
	}, {
		name:       "lock covers more than the requested architectures",
		contents:   LockContents{Packages: pkgs("x86_64", "aarch64"), Repositories: repos("x86_64", "aarch64")},
		requested:  archs("arm64"),
		wantLocked: archs("amd64", "arm64"),
	}, {
		name:       "apk and oci names are the same architecture",
		contents:   LockContents{Packages: pkgs("x86_64", "arm64", "armhf", "loongarch64", "x86")},
		requested:  archs("amd64", "aarch64", "arm/v6", "loong64", "386"),
		wantLocked: archs("386", "amd64", "arm/v6", "arm64", "loong64"),
	}, {
		name:        "missing architectures are deduplicated and keep the requested order",
		contents:    LockContents{Packages: pkgs("x86_64")},
		requested:   archs("s390x", "aarch64", "amd64", "arm64", "s390x"),
		wantLocked:  archs("amd64"),
		wantMissing: archs("s390x", "arm64"),
	}, {
		// An architecture can be locked without resolving a single package,
		// e.g. when the base image already provides everything requested.
		name:       "architecture without locked packages is covered by its repositories",
		contents:   LockContents{Packages: pkgs("x86_64"), Repositories: repos("x86_64", "aarch64")},
		requested:  archs("amd64", "arm64"),
		wantLocked: archs("amd64", "arm64"),
	}, {
		name:        "empty package list is still tied to the locked architectures",
		contents:    LockContents{Repositories: repos("x86_64")},
		requested:   archs("amd64", "arm64"),
		wantLocked:  archs("amd64"),
		wantMissing: archs("arm64"),
	}, {
		name:       "build repositories count",
		contents:   LockContents{BuildRepositories: repos("aarch64")},
		requested:  archs("arm64"),
		wantLocked: archs("arm64"),
	}, {
		name:       "runtime repositories count",
		contents:   LockContents{RuntimeOnlyRepositories: repos("aarch64")},
		requested:  archs("arm64"),
		wantLocked: archs("arm64"),
	}, {
		// Nothing in such a lock file says which architectures it was
		// generated for, so nothing can be reported as missing.
		name:      "lock without per-architecture records",
		requested: archs("amd64", "arm64"),
	}, {
		name:      "records without an architecture are ignored",
		contents:  LockContents{Packages: pkgs(""), Repositories: repos("")},
		requested: archs("amd64"),
	}, {
		name:       "nothing requested",
		contents:   LockContents{Packages: pkgs("x86_64")},
		wantLocked: archs("amd64"),
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := Lock{Contents: tt.contents}

			if diff := cmp.Diff(tt.wantLocked, l.Architectures()); diff != "" {
				t.Errorf("Architectures() mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.wantMissing, l.MissingArchitectures(tt.requested)); diff != "" {
				t.Errorf("MissingArchitectures(%v) mismatch (-want +got):\n%s", tt.requested, diff)
			}
		})
	}
}
