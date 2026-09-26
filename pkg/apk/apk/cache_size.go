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
	"os"
	"strconv"

	"github.com/chainguard-dev/clog"
)

// Environment variables that override the sizes of the process-wide
// in-memory caches. Both default to 64 entries. Every entry pins a parsed
// index generation (index cache) or a full package resolver built from one
// (resolver and disqualify caches), so raising either trades memory for hit
// rate. Long-running multi-tenant services that resolve against many distinct
// repository sets can raise them; the apko CLI does not need to.
const (
	// IndexCacheEntriesEnv sets how many parsed APKINDEX generations stay in
	// memory.
	IndexCacheEntriesEnv = "APKO_INDEX_CACHE_ENTRIES"
	// ResolverCacheEntriesEnv sets how many distinct index combinations the
	// resolver and disqualify caches each retain.
	ResolverCacheEntriesEnv = "APKO_RESOLVER_CACHE_ENTRIES"

	defaultCacheEntries = 64
)

// cacheEntriesFromEnv returns the positive integer in the named environment
// variable, or def when the variable is unset. A value that is not a positive
// integer is ignored with a warning, so a typo cannot disable a cache.
func cacheEntriesFromEnv(name string, def int) int {
	raw, ok := os.LookupEnv(name)
	if !ok {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		clog.Warnf("ignoring %s=%q: want a positive integer, using default %d", name, raw, def)
		return def
	}
	return n
}
