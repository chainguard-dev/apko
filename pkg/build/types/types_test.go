// Copyright 2022, 2023 Chainguard, Inc.
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
	}, {
		// Unknown arch strings are accepted.
		desc: "unknown arch",
		in:   []string{"apples", "bananas"},
		want: []Architecture{"apples", "bananas"},
	}, {
		desc: "all",
		in:   []string{"all"},
		want: AllArchs,
	}, {
		// If 'all' is present and isn't the only element, it will be interpreted as an architecture.
		desc: "uh oh all",
		in:   []string{"all", "riscv64"},
		want: []Architecture{"all", riscv64},
	}} {
		t.Run(c.desc, func(t *testing.T) {
			got := ParseArchitectures(c.in)
			require.Equal(t, c.want, got)
		})
	}
}

func TestOCIPlatform(t *testing.T) {
	for _, c := range []struct {
		desc string
		in   string
		want string
	}{{
		desc: "x86_64",
		in:   "x86_64",
		want: "amd64",
	}, {
		desc: "amd64",
		in:   "amd64",
		want: "amd64",
	}, {
		desc: "arm64",
		in:   "arm64",
		want: "arm64",
	}, {
		desc: "aarch64",
		in:   "aarch64",
		want: "arm64",
	}} {
		t.Run(c.desc, func(t *testing.T) {
			got := Architecture(c.in)
			require.Equal(t, c.want, got.ToOCIPlatform().Architecture)
		})
	}
}
