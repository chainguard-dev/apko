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

import "sort"

type User struct {
	UserName string
	UID      uint32
	GID      uint32
}

type Group struct {
	GroupName string
	GID       uint32
	Members   []string
}

type ImageConfiguration struct {
	Contents struct {
		Repositories []string
		Keyring      []string
		Packages     []string
	}
	Entrypoint struct {
		Type    string
		Command string

		// TBD: presently a map of service names and the command to run
		Services map[interface{}]interface{}
	}
	Accounts struct {
		RunAs  string `yaml:"run-as"`
		Users  []User
		Groups []Group
	}
	Archs []Architecture
}

type Architecture string

const (
	amd64   Architecture = "amd64"
	arm64   Architecture = "arm64"
	ppc64le Architecture = "ppc64le"
	s390x   Architecture = "s390x"
	_386    Architecture = "386"
	riscv64 Architecture = "riscv64"
	// TODO: armv7 and armhf (av6)
)

var AllArchs = []Architecture{amd64, arm64, ppc64le, s390x, _386, riscv64}

func (a Architecture) ToAPK() string {
	switch a {
	case _386:
		return "x86"
	case amd64:
		return "x86_64"
	case arm64:
		return "aarch64"
	default:
		return string(a)
	}
}

func ParseArchitectures(in []string) []Architecture {
	uniq := map[Architecture]struct{}{}
	for _, s := range in {
		a := Architecture(s)
		switch s {
		case "x86":
			a = _386
		case "x86_64":
			a = amd64
		case "aarch64":
			a = arm64
		}
		uniq[a] = struct{}{}
	}
	archs := make([]Architecture, 0, len(uniq))
	for k := range uniq {
		archs = append(archs, k)
	}
	sort.Slice(archs, func(i, j int) bool {
		return i < j
	})
	return archs
}
