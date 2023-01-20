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

package impl

func uniqify[T comparable](s []T) []T {
	seen := make(map[T]struct{}, len(s))
	uniq := make([]T, 0, len(s))
	for _, v := range s {
		if _, ok := seen[v]; ok {
			continue
		}

		uniq = append(uniq, v)
		seen[v] = struct{}{}
	}

	return uniq
}
