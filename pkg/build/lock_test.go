// Copyright 2024 Chainguard, Inc.
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
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"k8s.io/apimachinery/pkg/util/sets"

	"chainguard.dev/apko/pkg/build/types"
	pkglock "chainguard.dev/apko/pkg/lock"
)

func TestUnify(t *testing.T) {
	tests := []struct {
		name        string
		originals   []string
		inputs      []resolved
		want        map[string][]string
		wantMissing map[string][]string
		wantDiag    error
	}{{
		name: "empty",
		want: map[string][]string{"index": {}},
	}, {
		name:      "no inputs",
		originals: []string{"foo", "bar", "baz"},
		want:      map[string][]string{"index": {}},
	}, {
		name:      "simple single arch",
		originals: []string{"foo", "bar", "baz"},
		inputs: []resolved{{
			arch:     "amd64",
			packages: sets.New("foo", "bar", "baz"),
			versions: map[string]string{
				"foo": "1.2.3",
				"bar": "2.4.6",
				"baz": "0.0.1",
			},
		}},
		want: map[string][]string{
			"amd64": {
				"bar=2.4.6",
				"baz=0.0.1",
				"foo=1.2.3",
			},
			"index": {
				"bar=2.4.6",
				"baz=0.0.1",
				"foo=1.2.3",
			},
		},
	}, {
		name:      "locked versions",
		originals: []string{"foo=1.2.3", "bar=2.4.6", "baz=0.0.1"},
		inputs: []resolved{{
			arch:     "amd64",
			packages: sets.New("foo", "bar", "baz"),
			versions: map[string]string{
				"foo": "1.2.3",
				"bar": "2.4.6",
				"baz": "0.0.1",
			},
		}},
		want: map[string][]string{
			"amd64": {
				"bar=2.4.6",
				"baz=0.0.1",
				"foo=1.2.3",
			},
			"index": {
				"bar=2.4.6",
				"baz=0.0.1",
				"foo=1.2.3",
			},
		},
	}, {
		name:      "transitive dependency",
		originals: []string{"foo", "bar", "baz"},
		inputs: []resolved{{
			arch:     "amd64",
			packages: sets.New("foo", "bar", "baz", "bonus"),
			versions: map[string]string{
				"foo":   "1.2.3",
				"bar":   "2.4.6",
				"baz":   "0.0.1",
				"bonus": "5.4.3",
			},
		}},
		want: map[string][]string{
			"amd64": {
				"bar=2.4.6",
				"baz=0.0.1",
				"bonus=5.4.3",
				"foo=1.2.3",
			},
			"index": {
				"bar=2.4.6",
				"baz=0.0.1",
				"bonus=5.4.3",
				"foo=1.2.3",
			},
		},
	}, {
		name:      "multiple matching architectures",
		originals: []string{"foo", "bar", "baz"},
		inputs: []resolved{{
			arch:     "amd64",
			packages: sets.New("foo", "bar", "baz", "bonus"),
			versions: map[string]string{
				"foo":   "1.2.3",
				"bar":   "2.4.6",
				"baz":   "0.0.1",
				"bonus": "5.4.3",
			},
			provided: map[string]sets.Set[string]{
				"foo": sets.New("abc", "ogg"),
				"bar": sets.New("def"),
			},
		}, {
			arch:     "arm64",
			packages: sets.New("foo", "bar", "baz", "bonus"),
			versions: map[string]string{
				"foo":   "1.2.3",
				"bar":   "2.4.6",
				"baz":   "0.0.1",
				"bonus": "5.4.3",
			},
			provided: map[string]sets.Set[string]{
				"foo": sets.New("abc"),
				"bar": sets.New("def", "ogg"),
			},
		}},
		want: map[string][]string{
			"amd64": {
				"bar=2.4.6",
				"baz=0.0.1",
				"bonus=5.4.3",
				"foo=1.2.3",
			},
			"arm64": {
				"bar=2.4.6",
				"baz=0.0.1",
				"bonus=5.4.3",
				"foo=1.2.3",
			},
			"index": {
				"bar=2.4.6",
				"baz=0.0.1",
				"bonus=5.4.3",
				"foo=1.2.3",
			},
		},
	}, {
		name:      "mismatched transitive dependency",
		originals: []string{"foo", "bar", "baz"},
		inputs: []resolved{{
			arch:     "amd64",
			packages: sets.New("foo", "bar", "baz", "bonus"),
			versions: map[string]string{
				"foo":   "1.2.3",
				"bar":   "2.4.6",
				"baz":   "0.0.1",
				"bonus": "5.4.3-r0",
			},
		}, {
			arch:     "arm64",
			packages: sets.New("foo", "bar", "baz", "bonus"),
			versions: map[string]string{
				"foo":   "1.2.3",
				"bar":   "2.4.6",
				"baz":   "0.0.1",
				"bonus": "5.4.3-r1",
			},
		}},
		want: map[string][]string{
			"amd64": {
				"bar=2.4.6",
				"baz=0.0.1",
				"bonus=5.4.3-r0",
				"foo=1.2.3",
			},
			"arm64": {
				"bar=2.4.6",
				"baz=0.0.1",
				"bonus=5.4.3-r1",
				"foo=1.2.3",
			},
			"index": {
				"bar=2.4.6",
				"baz=0.0.1",
				"foo=1.2.3",
			},
		},
		wantMissing: map[string][]string{
			"amd64": {"bonus"},
			"arm64": {"bonus"},
		},
	}, {
		name:      "provided direct dependency",
		originals: []string{"foo", "bar", "baz"},
		inputs: []resolved{{
			arch:     "amd64",
			packages: sets.New("foo", "baz", "bonus"),
			versions: map[string]string{
				"foo":   "1.2.3",
				"baz":   "0.0.1",
				"bonus": "5.4.3",
			},
			provided: map[string]sets.Set[string]{
				"bonus": sets.New("bar"),
			},
		}, {
			arch:     "arm64",
			packages: sets.New("foo", "baz", "bonus"),
			versions: map[string]string{
				"foo":   "1.2.3",
				"baz":   "0.0.1",
				"bonus": "5.4.3",
			},
			provided: map[string]sets.Set[string]{
				"bonus": sets.New("bar"),
			},
		}},
		want: map[string][]string{
			"amd64": {
				"baz=0.0.1",
				"bonus=5.4.3",
				"foo=1.2.3",
			},
			"arm64": {
				"baz=0.0.1",
				"bonus=5.4.3",
				"foo=1.2.3",
			},
			"index": {
				"baz=0.0.1",
				"bonus=5.4.3",
				"foo=1.2.3",
			},
		},
	}, {
		name:      "mismatched direct dependency",
		originals: []string{"foo", "bar", "baz"},
		inputs: []resolved{{
			arch:     "amd64",
			packages: sets.New("foo", "bar", "baz", "bonus"),
			versions: map[string]string{
				"foo":   "1.2.3",
				"bar":   "2.4.6-r0",
				"baz":   "0.0.1",
				"bonus": "5.4.3",
			},
		}, {
			arch:     "arm64",
			packages: sets.New("foo", "bar", "baz", "bonus"),
			versions: map[string]string{
				"foo":   "1.2.3",
				"bar":   "2.4.6-r1",
				"baz":   "0.0.1",
				"bonus": "5.4.3",
			},
		}},
		wantDiag: errors.New("unable to lock packages to a consistent version: map[bar:[2.4.6-r0 (amd64) 2.4.6-r1 (arm64)]]"),
	}, {
		name:      "mismatched direct dependency (with constraint)",
		originals: []string{"foo", "bar>2.4.6", "baz"},
		inputs: []resolved{{
			arch:     "amd64",
			packages: sets.New("foo", "bar", "baz", "bonus"),
			versions: map[string]string{
				"foo":   "1.2.3",
				"bar":   "2.4.6-r0",
				"baz":   "0.0.1",
				"bonus": "5.4.3",
			},
		}, {
			arch:     "arm64",
			packages: sets.New("foo", "bar", "baz", "bonus"),
			versions: map[string]string{
				"foo":   "1.2.3",
				"bar":   "2.4.6-r1",
				"baz":   "0.0.1",
				"bonus": "5.4.3",
			},
		}},
		// want: []string{
		// 	"bar>2.4.6", // Check that we keep our input constraint
		// 	"baz=0.0.1",
		// 	"bonus=5.4.3",
		// 	"foo=1.2.3",
		// },
		wantDiag: errors.New("unable to lock packages to a consistent version: map[bar:[2.4.6-r0 (amd64) 2.4.6-r1 (arm64)]]"),
	}, {
		name:      "single-architecture resolved dependency",
		originals: []string{"foo", "bar", "baz"},
		inputs: []resolved{{
			arch:     "amd64",
			packages: sets.New("foo", "bar", "baz", "intel-fast-as-f-math"),
			versions: map[string]string{
				"foo":                  "1.2.3",
				"bar":                  "2.4.6",
				"baz":                  "0.0.1",
				"intel-fast-as-f-math": "5.4.3",
			},
		}, {
			arch:     "arm64",
			packages: sets.New("foo", "bar", "baz", "arm-energy-efficient-as-f-arithmetic"),
			versions: map[string]string{
				"foo":                                  "1.2.3",
				"bar":                                  "2.4.6",
				"baz":                                  "0.0.1",
				"arm-energy-efficient-as-f-arithmetic": "9.8.7",
			},
		}},
		want: map[string][]string{
			"amd64": {
				"bar=2.4.6",
				"baz=0.0.1",
				"foo=1.2.3",
				"intel-fast-as-f-math=5.4.3",
			},
			"arm64": {
				"arm-energy-efficient-as-f-arithmetic=9.8.7",
				"bar=2.4.6",
				"baz=0.0.1",
				"foo=1.2.3",
			},
			"index": {
				"bar=2.4.6",
				"baz=0.0.1",
				"foo=1.2.3",
			},
		},
		wantMissing: map[string][]string{
			"amd64": {"intel-fast-as-f-math"},
			"arm64": {"arm-energy-efficient-as-f-arithmetic"},
		},
	}, {
		name:      "sorting with dashes",
		originals: []string{"foo", "foo-bar"},
		inputs: []resolved{{
			arch:     "amd64",
			packages: sets.New("foo", "foo-bar"),
			versions: map[string]string{
				"foo":     "1.2.3",
				"foo-bar": "2.4.6",
			},
		}},
		want: map[string][]string{
			"amd64": {
				// This comes first because '-' sorts before '='.
				"foo-bar=2.4.6",
				"foo=1.2.3",
			},
			"index": {
				// This comes first because '-' sorts before '='.
				"foo-bar=2.4.6",
				"foo=1.2.3",
			},
		},
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, gotMissing, gotDiag := unify(test.originals, test.inputs)
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("(-want, +got) = %s", diff)
			}
			if diff := cmp.Diff(test.wantMissing, gotMissing); diff != "" {
				t.Errorf("(-want, +got) = %s", diff)
			}
			if (test.wantDiag != nil) != (gotDiag != nil) {
				t.Errorf("unify() = %v, wanted %v", gotDiag, test.wantDiag)
			} else if test.wantDiag != nil && gotDiag != nil && test.wantDiag.Error() != gotDiag.Error() {
				t.Errorf("unify() = %v, wanted %v", gotDiag, test.wantDiag)
			}
		})
	}
}

func TestVerifyLockfileArchitectures(t *testing.T) {
	lockedFor := func(apkArchs ...string) pkglock.Lock {
		var l pkglock.Lock
		for _, arch := range apkArchs {
			l.Contents.Packages = append(l.Contents.Packages, pkglock.LockPkg{Name: "pkg", Version: "1.2.3", Architecture: arch})
			l.Contents.Repositories = append(l.Contents.Repositories, pkglock.LockRepo{Name: "repo/" + arch, Architecture: arch})
		}
		return l
	}

	tests := []struct {
		name      string
		lock      pkglock.Lock
		requested []types.Architecture
		wantErr   string
	}{{
		name:      "partially covered",
		lock:      lockedFor("x86_64"),
		requested: []types.Architecture{"amd64", "arm64"},
		wantErr:   "lockfile \"apko.lock.json\" does not cover requested architecture arm64 (aarch64): it was generated for amd64 (x86_64); regenerate it with `apko lock --arch=amd64,arm64`",
	}, {
		name:      "not covered at all",
		lock:      lockedFor("x86_64"),
		requested: []types.Architecture{"arm64"},
		// The suggestion keeps the architectures that are already locked.
		wantErr: "lockfile \"apko.lock.json\" does not cover requested architecture arm64 (aarch64): it was generated for amd64 (x86_64); regenerate it with `apko lock --arch=amd64,arm64`",
	}, {
		name:      "several architectures missing",
		lock:      lockedFor("x86_64", "aarch64"),
		requested: []types.Architecture{"amd64", "s390x", "armv7", "riscv64"},
		wantErr:   "lockfile \"apko.lock.json\" does not cover requested architectures s390x, arm/v7 (armv7), riscv64: it was generated for amd64 (x86_64), arm64 (aarch64); regenerate it with `apko lock --arch=amd64,arm/v7,arm64,riscv64,s390x`",
	}, {
		name:      "covered",
		lock:      lockedFor("x86_64", "aarch64"),
		requested: []types.Architecture{"amd64", "arm64"},
	}, {
		name:      "covered subset",
		lock:      lockedFor("x86_64", "aarch64"),
		requested: []types.Architecture{"arm64"},
	}, {
		name:      "apk-style names in the request",
		lock:      lockedFor("x86_64", "aarch64"),
		requested: []types.Architecture{"x86_64", "aarch64"},
	}, {
		name:      "lock without per-architecture records",
		requested: []types.Architecture{"amd64", "arm64"},
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := verifyLockfileArchitectures("apko.lock.json", test.lock, test.requested)
			switch {
			case test.wantErr == "" && err != nil:
				t.Errorf("verifyLockfileArchitectures() = %v, wanted no error", err)
			case test.wantErr != "" && err == nil:
				t.Errorf("verifyLockfileArchitectures() = nil, wanted %q", test.wantErr)
			case test.wantErr != "" && err.Error() != test.wantErr:
				t.Errorf("verifyLockfileArchitectures() = %q, wanted %q", err, test.wantErr)
			}
		})
	}
}
