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

package apk

import (
	"reflect"
	"sync"
	"weak"
)

// Repository indexes overlap heavily: consecutive generations of one index
// share almost all of their packages, and indexes of related repositories
// carry large common subsets. Interning parsed packages lets all of them
// share a single Package per distinct package instead of a copy per index.
// Entries hold weak pointers, so the table itself pins nothing.
//
// Sharing requires that packages parsed from repository indexes are never
// mutated; they are treated as immutable everywhere.
var packageInterner = struct {
	sync.Mutex
	m map[internKey]weak.Pointer[Package]
}{m: map[internKey]weak.Pointer[Package]{}}

type internKey struct {
	name     string
	checksum string
}

// internPackage returns the canonical *Package for pkg: a previously interned
// package with an identical record, or pkg itself if none is registered yet.
// Packages without a checksum are not interned.
//
// The {name, checksum} pair only buckets candidates; identity is confirmed
// with reflect.DeepEqual over the whole package, so two records share a
// Package only when every field matches. That keeps interning safe across
// repository trust boundaries - a crafted index cannot donate its
// dependencies to another repository's package by matching the control hash
// alone - and cannot silently drop a field the way a hand-written comparison
// could.
func internPackage(pkg *Package) *Package {
	if len(pkg.Checksum) == 0 {
		return pkg
	}
	key := internKey{name: pkg.Name, checksum: string(pkg.Checksum)}

	packageInterner.Lock()
	defer packageInterner.Unlock()

	if wp, ok := packageInterner.m[key]; ok {
		if canonical := wp.Value(); canonical != nil {
			if reflect.DeepEqual(pkg, canonical) {
				return canonical
			}
			// A live but different package holds the bucket (a control-hash
			// collision or a poisoning attempt): keep both distinct.
			return pkg
		}
	}

	// Weak so the payload is collected once no live index references it. A
	// dead entry reads back as a miss and is overwritten when its record
	// recurs; one forms only when a record leaves every live index at once,
	// rare for largely append-only indexes, so tombstones accumulate slowly.
	packageInterner.m[key] = weak.Make(pkg)
	return pkg
}
