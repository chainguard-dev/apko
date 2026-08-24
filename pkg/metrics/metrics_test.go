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

package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

func TestCacheAccesses(t *testing.T) {
	registry := prometheus.NewPedanticRegistry()
	require.NoError(t, Register(registry))
	before := cacheValues(t, registry)

	RecordIndexCacheAccess(CacheResultHit)
	RecordIndexCacheAccess(CacheResultHit)
	RecordIndexCacheAccess(CacheResultMiss)
	RecordResolverCacheAccess(CacheResultBypass)

	after := cacheValues(t, registry)
	for key, value := range before {
		after[key] -= value
	}

	require.Equal(t, map[string]float64{
		"index/bypass":    0,
		"index/hit":       2,
		"index/miss":      1,
		"resolver/bypass": 1,
		"resolver/hit":    0,
		"resolver/miss":   0,
	}, after)
}

func cacheValues(t *testing.T, registry *prometheus.Registry) map[string]float64 {
	t.Helper()
	families, err := registry.Gather()
	require.NoError(t, err)

	values := map[string]float64{}
	for _, family := range families {
		if family.GetName() != "apko_cache_accesses_total" {
			continue
		}
		for _, metric := range family.Metric {
			labels := map[string]string{}
			for _, label := range metric.Label {
				labels[label.GetName()] = label.GetValue()
			}
			values[labels["cache"]+"/"+labels["result"]] = metric.GetCounter().GetValue()
		}
	}
	return values
}
