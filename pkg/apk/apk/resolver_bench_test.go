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
	"context"
	"fmt"
	"testing"
)

// BenchmarkNewPkgResolver builds a resolver over a synthetic index shaped
// roughly like Wolfi: several versions per name and a handful of provides per
// package. Allocation counts are the interesting number here.
func BenchmarkNewPkgResolver(b *testing.B) {
	const names, versions = 20000, 3
	idx := &APKIndex{}
	for n := range names {
		for v := range versions {
			idx.Packages = append(idx.Packages, &Package{
				Name:    fmt.Sprintf("pkg-%d", n),
				Version: fmt.Sprintf("1.%d.0-r0", v),
				Arch:    "x86_64",
				Provides: []string{
					fmt.Sprintf("cmd:tool-%d=1.%d.0-r0", n, v),
					fmt.Sprintf("so:lib%d.so.1=1", n),
					fmt.Sprintf("pc:lib%d=1.%d.0", n, v),
				},
			})
		}
	}
	repo := &Repository{URI: "https://example.invalid/os/x86_64"}
	indexes := []NamedIndex{NewNamedRepositoryWithIndex("", repo.WithIndex(idx))}

	// Warm the shared provides parse cache so it does not dominate.
	_ = newPkgResolver(context.Background(), indexes)

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = newPkgResolver(context.Background(), indexes)
	}
}
