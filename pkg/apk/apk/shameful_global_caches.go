// Copyright 2023 Chainguard, Inc.
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
	"context"
	"maps"
	"slices"
	"strings"
	"sync"
)

// It is expensive to parse every version in the APKINDEX and grow a bunch of maps.
// This caches a PkgResolver based on the input []NamedIndex.
var globalResolverCache = &resolverCache{}

type resolverCache struct {
	sync.Mutex
	children map[NamedIndex]*resolverCache
	pr       *PkgResolver
}

func (r *resolverCache) find(indexes []NamedIndex) *PkgResolver {
	if len(indexes) == 0 {
		return r.pr
	}

	if r.children == nil {
		return nil
	}

	child, ok := r.children[indexes[0]]
	if !ok {
		return nil
	}

	return child.find(indexes[1:])
}

func (r *resolverCache) fill(indexes []NamedIndex, pr *PkgResolver) {
	if len(indexes) == 0 {
		r.pr = pr
		return
	}

	if r.children == nil {
		r.children = make(map[NamedIndex]*resolverCache)
	}

	child, ok := r.children[indexes[0]]
	if !ok {
		child = &resolverCache{}
		r.children[indexes[0]] = child
	}

	child.fill(indexes[1:], pr)
}

func (r *resolverCache) Get(ctx context.Context, indexes []NamedIndex) *PkgResolver {
	r.Lock()
	defer r.Unlock()

	if pr := r.find(indexes); pr != nil {
		return pr.Clone()
	}

	pr := newPkgResolver(ctx, indexes)
	r.fill(indexes, pr)

	return pr.Clone()
}

// It is expensive to compute the complement
// This a PkgResolver based on the input []NamedIndex.
var globalDisqualifyCache = &disqualifyCache{}

type disqualifyCache struct {
	sync.Mutex
	children map[NamedIndex]*disqualifyCache
	dq       map[*RepositoryPackage]string
}

func (r *disqualifyCache) find(indexes []NamedIndex) map[*RepositoryPackage]string {
	if len(indexes) == 0 {
		return r.dq
	}

	if r.children == nil {
		return nil
	}

	child, ok := r.children[indexes[0]]
	if !ok {
		return nil
	}

	return child.find(indexes[1:])
}

func (r *disqualifyCache) fill(indexes []NamedIndex, dq map[*RepositoryPackage]string) {
	if len(indexes) == 0 {
		r.dq = dq
		return
	}

	if r.children == nil {
		r.children = make(map[NamedIndex]*disqualifyCache)
	}

	child, ok := r.children[indexes[0]]
	if !ok {
		child = &disqualifyCache{}
		r.children[indexes[0]] = child
	}

	child.fill(indexes[1:], dq)
}

// It is expensive to compute the difference between every architecture.
// This caches that difference based on the input []NamedIndex for every architecture.
func (r *disqualifyCache) Get(ctx context.Context, byArch map[string][]NamedIndex) map[*RepositoryPackage]string {
	r.Lock()
	defer r.Unlock()

	indexes := slices.Concat(slices.Collect(maps.Values(byArch))...)
	slices.SortFunc(indexes, func(a, b NamedIndex) int {
		return strings.Compare(a.Name(), b.Name())
	})
	if dq := r.find(indexes); dq != nil {
		return maps.Clone(dq)
	}

	dq := disqualifyDifference(ctx, byArch)
	r.fill(indexes, dq)

	return maps.Clone(dq)
}
