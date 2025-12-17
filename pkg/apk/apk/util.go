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
	"errors"
	"fmt"
	"io"
	"io/fs"
	"slices"
	"strings"
)

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

func controlValue(controlFs fs.FS, want ...string) (map[string][]string, error) {
	f, err := controlFs.Open(".PKGINFO")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("control file not found")
		}
		return nil, fmt.Errorf("opening .PKGINFO: %w", err)
	}
	defer f.Close()

	b, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("unable to read .PKGINFO from control tar.gz file: %w", err)
	}
	mapping := map[string][]string{}
	lines := strings.SplitSeq(string(b), "\n")
	for line := range lines {
		parts := strings.Split(line, "=")
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		if !slices.Contains(want, key) {
			continue
		}

		values, ok := mapping[key]
		if !ok {
			values = []string{}
		}

		value := strings.TrimSpace(parts[1])
		values = append(values, value)

		mapping[key] = values
	}
	return mapping, nil
}
