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
	"sort"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

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

// Architecture represents a CPU architecture for the container image.
type Architecture struct{ s string }

func (a Architecture) String() string { return a.s }

var (
	_386    = Architecture{"386"}
	amd64   = Architecture{"amd64"}
	arm64   = Architecture{"arm64"}
	armv6   = Architecture{"arm/v6"}
	armv7   = Architecture{"arm/v7"}
	ppc64le = Architecture{"ppc64le"}
	riscv64 = Architecture{"riscv64"}
	s390x   = Architecture{"s390x"}
)

// AllArchs contains the standard set of supported architectures, which are
// used by `apko publish` when no architectures are specified.
var AllArchs = []Architecture{
	_386,
	amd64,
	arm64,
	armv6,
	armv7,
	ppc64le,
	riscv64,
	s390x,
}

// ToAPK returns the apk-style equivalent string for the Architecture.
func (a Architecture) ToAPK() string {
	switch a {
	case _386:
		return "x86"
	case amd64:
		return "x86_64"
	case arm64:
		return "aarch64"
	case armv6:
		return "armhf"
	case armv7:
		return "armv7"
	default:
		return a.s
	}
}

func (a Architecture) ToOCIPlatform() *v1.Platform {
	plat := v1.Platform{OS: "linux"}
	switch a {
	case armv6:
		plat.Architecture = "arm"
		plat.Variant = "v6"
	case armv7:
		plat.Architecture = "arm"
		plat.Variant = "v7"
	default:
		plat.Architecture = a.s
	}
	return &plat
}

func (a Architecture) ToQEmu() string {
	switch a {
	case _386:
		return "i386"
	case amd64:
		return "x86_64"
	case arm64:
		return "aarch64"
	case armv6:
		return "arm"
	case armv7:
		return "arm"
	default:
		return a.s
	}
}

// ParseArchitecture parses a single architecture in string form, and returns
// the equivalent Architecture value.
//
// Any apk-style arch string (e.g., "x86_64") is converted to the OCI-style
// equivalent ("amd64").
func ParseArchitecture(s string) Architecture {
	switch s {
	case "x86":
		return _386
	case "x86_64":
		return amd64
	case "aarch64":
		return arm64
	case "armhf":
		return armv6
	case "armv7":
		return armv7
	}
	return Architecture{s}
}

// ParseArchitectures parses architecture values in string form, and returns
// the equivalent slice of Architectures.
//
// apk-style arch strings (e.g., "x86_64") are converted to the OCI-style
// equivalent ("amd64"). Values are deduped, and the resulting slice is sorted
// for reproducibility.
func ParseArchitectures(in []string) []Architecture {
	uniq := map[Architecture]struct{}{}
	for _, s := range in {
		a := ParseArchitecture(s)
		uniq[a] = struct{}{}
	}
	archs := make([]Architecture, 0, len(uniq))
	for k := range uniq {
		archs = append(archs, k)
	}
	sort.Slice(archs, func(i, j int) bool {
		return archs[i].s < archs[j].s
	})
	return archs
}
