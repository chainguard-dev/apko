// Copyright 2022 Chainguard, Inc.
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

package types

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseArchitectures(t *testing.T) {
	for _, c := range []struct {
		desc string
		in   []string
		want []Architecture
	}{{
		desc: "empty",
		in:   []string{},
		want: []Architecture{},
	}, {
		desc: "sort",
		in:   []string{"riscv64", "amd64", "arm/v6"},
		want: []Architecture{amd64, armv6, riscv64},
	}, {
		desc: "dedupe",
		in:   []string{"amd64", "amd64", "arm64"},
		want: []Architecture{amd64, arm64},
	}, {
		desc: "dedupe w/ apk style",
		in:   []string{"x86_64", "amd64", "arm64", "arm/v6", "armhf"},
		want: []Architecture{amd64, armv6, arm64},
	}} {
		t.Run(c.desc, func(t *testing.T) {
			got := ParseArchitectures(c.in)
			require.Equal(t, c.want, got)
		})
	}
}
