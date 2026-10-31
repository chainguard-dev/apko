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

package build

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOrderedUniqueStringsPreservesOrder(t *testing.T) {
	got := orderedUniqueStrings(
		[]string{"https://repo-first.example", "https://repo-shared.example"},
		[]string{"https://repo-second.example", "https://repo-shared.example"},
		[]string{"https://repo-third.example"},
	)

	require.Equal(t, []string{
		"https://repo-first.example",
		"https://repo-shared.example",
		"https://repo-second.example",
		"https://repo-third.example",
	}, got)
}

func TestOrderedUniqueStringsEmptyInput(t *testing.T) {
	require.Empty(t, orderedUniqueStrings())
	require.Empty(t, orderedUniqueStrings([]string{}, []string{}))
}
