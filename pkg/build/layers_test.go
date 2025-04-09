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
	"fmt"
	"slices"
	"testing"

	"chainguard.dev/apko/pkg/apk/apk"
)

func size(pkgs ...*apk.Package) uint64 {
	var total uint64
	for _, pkg := range pkgs {
		total += pkg.InstalledSize
	}
	return total
}

func TestGroupByOriginAndSize(t *testing.T) {
	crane := &apk.Package{Name: "crane", Origin: "crane", InstalledSize: 100}

	glibc := &apk.Package{Name: "glibc", Origin: "glibc", InstalledSize: 6113087}
	posix := &apk.Package{Name: "glibc-locale-posix", Origin: "glibc", InstalledSize: 417444}

	libcrypt1 := &apk.Package{Name: "libcrypt1", Origin: "glibc", Version: "2.38-r14", InstalledSize: 23508}
	libxcrypt := &apk.Package{Name: "libxcrypt", Origin: "libxcrypt", InstalledSize: 235761, Replaces: []string{"libcrypt1<2.38-r15"}}

	newcrypt1 := &apk.Package{Name: "libcrypt1", Origin: "glibc", Version: "2.38-r16", InstalledSize: 23508}

	repxcrypt := &apk.Package{Name: "libxcrypt", Origin: "libxcrypt", InstalledSize: 235761, Replaces: []string{"libcrypt1"}}
	for _, tc := range []struct {
		pkgs   []*apk.Package
		budget int
		want   []*group
		err    error
	}{{
		pkgs:   []*apk.Package{crane},
		budget: 1,
		want:   []*group{{pkgs: []*apk.Package{crane}, size: size(crane), tiebreaker: "crane"}},
	}, {
		// glibc and glibc-locale-posix should be grouped by origin
		pkgs:   []*apk.Package{crane, glibc, posix},
		budget: 2,
		want: []*group{
			{pkgs: []*apk.Package{glibc, posix}, size: size(glibc, posix), tiebreaker: "glibc-locale-posix"},
			{pkgs: []*apk.Package{crane}, size: size(crane), tiebreaker: "crane"},
		},
	}, {
		// reasonable default if budget is unspecified
		pkgs: []*apk.Package{crane, glibc, posix},
		want: []*group{
			{pkgs: []*apk.Package{crane, glibc, posix}, size: size(crane, glibc, posix), tiebreaker: "glibc-locale-posix"},
		},
	}, {
		// libxcrypt replace libcrypt1, so it should be merged into the glibc origin
		pkgs:   []*apk.Package{crane, glibc, posix, libcrypt1, libxcrypt},
		budget: 5,
		want: []*group{
			{pkgs: []*apk.Package{glibc, posix, libcrypt1, libxcrypt}, size: size(glibc, libcrypt1, libxcrypt, posix), tiebreaker: "libxcrypt"},
			{pkgs: []*apk.Package{crane}, size: size(crane), tiebreaker: "crane"},
		},
	}, {
		// libxcrypt replaces does not match the version constraint for "newcrypt1", so it doesn't get merged.
		pkgs:   []*apk.Package{crane, glibc, posix, newcrypt1, libxcrypt},
		budget: 5,
		want: []*group{
			{pkgs: []*apk.Package{glibc, posix, newcrypt1}, size: size(glibc, newcrypt1, posix), tiebreaker: "libcrypt1"},
			{pkgs: []*apk.Package{libxcrypt}, size: size(libxcrypt), tiebreaker: "libxcrypt"},
			{pkgs: []*apk.Package{crane}, size: size(crane), tiebreaker: "crane"},
		},
	}, {
		// "repxcrypt" replaces has no version, so it _does_ merge with "newcrypt1".
		pkgs:   []*apk.Package{crane, glibc, posix, newcrypt1, repxcrypt},
		budget: 5,
		want: []*group{
			{pkgs: []*apk.Package{glibc, posix, newcrypt1, repxcrypt}, size: size(glibc, newcrypt1, posix, repxcrypt), tiebreaker: "libxcrypt"},
			{pkgs: []*apk.Package{crane}, size: size(crane), tiebreaker: "crane"},
		},
	}, {
		// should be 3 groups but budget constricts that to 2
		pkgs:   []*apk.Package{crane, glibc, posix, newcrypt1, libxcrypt},
		budget: 2,
		want: []*group{
			{pkgs: []*apk.Package{glibc, posix, newcrypt1}, size: size(glibc, newcrypt1, posix), tiebreaker: "libcrypt1"},
			{pkgs: []*apk.Package{crane, libxcrypt}, size: size(crane, libxcrypt), tiebreaker: "libxcrypt"},
		},
	}} {
		got, err := groupByOriginAndSize(tc.pkgs, tc.budget)
		if err != nil && tc.err != nil {
			continue
		}

		if err != nil && tc.err == nil {
			t.Errorf("groupByOriginAndSize(%v, %d) unexpected error: %v", tc.pkgs, tc.budget, err)
		} else if err == nil && tc.err != nil {
			t.Errorf("groupByOriginAndSize(%v, %d) expected error: %v", tc.pkgs, tc.budget, tc.err)
		}

		if err := compareGroups(got, tc.want); err != nil {
			t.Errorf("groupByOriginAndSize(%v, %d) mismatch: %v", tc.pkgs, tc.budget, err)

			for i, g := range got {
				t.Logf("got[%d]: %v", i, g.pkgs)
			}
			for i, g := range tc.want {
				t.Logf("want[%d]: %v", i, g.pkgs)
			}
		}
	}
}

func compareGroups(a, b []*group) error {
	if len(a) != len(b) {
		return fmt.Errorf("len(a) = %d; len(b) = %d", len(a), len(b))
	}
	for i := range a {
		aa, bb := a[i], b[i]
		if len(aa.pkgs) != len(bb.pkgs) {
			return fmt.Errorf("len(a[%d].pkgs) = %d; len(b[%d].pkgs) = %d", i, len(aa.pkgs), i, len(bb.pkgs))
		}

		for j := range aa.pkgs {
			if aa.pkgs[j].Name != bb.pkgs[j].Name {
				return fmt.Errorf("a[%d].pkgs[%d] = %s; b[%d].pkgs[%d] = %s", i, j, aa.pkgs[j].Name, i, j, bb.pkgs[j].Name)
			}
		}

		if aa.size != bb.size {
			return fmt.Errorf("a[%d].size = %d; b[%d].size = %d", i, aa.size, i, bb.size)
		}
		if aa.tiebreaker != bb.tiebreaker {
			return fmt.Errorf("a[%d].tiebreaker = %s; b[%d].tiebreaker = %s", i, aa.tiebreaker, i, bb.tiebreaker)
		}
	}

	return nil
}

func TestAlignStacks(t *testing.T) {
	usr := []*file{{
		path: "usr",
	}, {
		path: "usr/lib",
	}}
	etc := []*file{{
		path: "etc",
	}, {
		path: "etc/apk",
	}, {
		path: "etc/apk/key",
	}}
	for i, tc := range []struct {
		stack  []*file
		before []*file
		diff   []*file
		after  []*file
	}{{
		stack:  usr,
		before: usr,
		after:  usr,
	}, {
		stack: usr,
		after: usr,
		diff:  usr,
	}, {
		stack:  usr,
		before: etc,
		after:  usr,
		diff:   usr,
	}, {
		stack:  etc,
		before: usr,
		after:  etc,
		diff:   etc,
	}, {
		stack:  etc[:2],
		before: etc,
		after:  etc[:2],
	}, {
		stack:  etc,
		before: etc[:2],
		after:  etc,
		diff:   etc[2:],
	}} {
		t.Run(fmt.Sprintf("case_%d", i), func(t *testing.T) {
			// clone to avoid mutating the usr and etc slices directly
			w := &layerWriter{stack: slices.Clone(tc.before)}

			if err := compareStacks(w.alignStacks(tc.stack), tc.diff); err != nil {
				t.Errorf("alignStacks() mismatch: %v", err)
			}
			if err := compareStacks(w.stack, tc.after); err != nil {
				t.Errorf("w.stack mismatch: %v", err)
			}
		})
	}
}

// NB: this only cares about path
func compareStacks(a, b []*file) error {
	if len(a) != len(b) {
		return fmt.Errorf("len(a) = %d; len(b) = %d", len(a), len(b))
	}

	for i := range len(a) {
		if a[i].path != b[i].path {
			return fmt.Errorf("a[%d] = %s; b[%d] = %s", i, a[i].path, i, b[i].path)
		}
	}

	return nil
}
