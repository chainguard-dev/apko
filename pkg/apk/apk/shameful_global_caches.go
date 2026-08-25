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

	apkometrics "chainguard.dev/apko/pkg/metrics"
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
	// A superseded index generation will never be requested again once the
	// in-flight resolutions holding it finish, and no future replacement
	// will purge it, so it must not (re-)enter the cache.
	if !currentAll(indexes) {
		apkometrics.RecordResolverCacheAccess(apkometrics.CacheResultBypass)
		return newPkgResolver(ctx, indexes)
	}

	r.Lock()
	defer r.Unlock()

	if pr := r.find(indexes); pr != nil {
		apkometrics.RecordResolverCacheAccess(apkometrics.CacheResultHit)
		return pr.Clone()
	}
	apkometrics.RecordResolverCacheAccess(apkometrics.CacheResultMiss)

	pr := newPkgResolver(ctx, indexes)
	r.fill(indexes, pr)

	// A generation replacement that raced the fill has already run its
	// purge, so purge its index ourselves.
	for _, idx := range indexes {
		if !globalIndexCache.isCurrent(idx) {
			r.forgetIndex(idx)
		}
	}

	return pr.Clone()
}

func currentAll(indexes []NamedIndex) bool {
	for _, idx := range indexes {
		if !globalIndexCache.isCurrent(idx) {
			return false
		}
	}
	return true
}

// ForgetIndex removes every cached entry whose index combination includes
// idx: a resolver over a superseded generation is superseded itself.
func (r *resolverCache) ForgetIndex(idx NamedIndex) {
	r.Lock()
	defer r.Unlock()

	r.forgetIndex(idx)
}

func (r *resolverCache) forgetIndex(idx NamedIndex) {
	delete(r.children, idx)
	for _, child := range r.children {
		child.forgetIndex(idx)
	}
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
	if !currentAll(indexes) {
		return disqualifyDifference(ctx, byArch)
	}

	slices.SortFunc(indexes, func(a, b NamedIndex) int {
		return strings.Compare(a.Name(), b.Name())
	})
	if dq := r.find(indexes); dq != nil {
		return maps.Clone(dq)
	}

	dq := disqualifyDifference(ctx, byArch)
	r.fill(indexes, dq)

	for _, idx := range indexes {
		if !globalIndexCache.isCurrent(idx) {
			r.forgetIndex(idx)
		}
	}

	return maps.Clone(dq)
}

// ForgetIndex removes every cached entry whose index combination includes
// idx: a difference over a superseded generation is superseded itself.
func (r *disqualifyCache) ForgetIndex(idx NamedIndex) {
	r.Lock()
	defer r.Unlock()

	r.forgetIndex(idx)
}

func (r *disqualifyCache) forgetIndex(idx NamedIndex) {
	delete(r.children, idx)
	for _, child := range r.children {
		child.forgetIndex(idx)
	}
}
