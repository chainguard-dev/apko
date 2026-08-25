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

// Package metrics exposes Prometheus metrics emitted by apko.
package metrics

import "github.com/prometheus/client_golang/prometheus"

const (
	cacheIndex    = "index"
	cacheResolver = "resolver"
)

// CacheResult describes the outcome of a cache access.
type CacheResult string

const (
	CacheResultBypass CacheResult = "bypass"
	CacheResultHit    CacheResult = "hit"
	CacheResultMiss   CacheResult = "miss"
)

var cacheAccesses = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "apko_cache_accesses_total",
		Help: "The number of APK cache accesses by cache and result.",
	},
	[]string{"cache", "result"},
)

func init() {
	for _, cache := range []string{cacheIndex, cacheResolver} {
		for _, result := range []CacheResult{CacheResultBypass, CacheResultHit, CacheResultMiss} {
			cacheAccesses.WithLabelValues(cache, string(result))
		}
	}
}

// Register registers APK metrics with registerer.
func Register(registerer prometheus.Registerer) error {
	return registerer.Register(cacheAccesses)
}

// RecordIndexCacheAccess records an index cache access.
func RecordIndexCacheAccess(result CacheResult) {
	cacheAccesses.WithLabelValues(cacheIndex, string(result)).Inc()
}

// RecordResolverCacheAccess records a package resolver cache access.
func RecordResolverCacheAccess(result CacheResult) {
	cacheAccesses.WithLabelValues(cacheResolver, string(result)).Inc()
}
