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
	"fmt"
	"runtime"
	"sort"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

type User struct {
	// Required: The name of the user
	UserName string
	// Required: The user ID
	UID uint32
	// Required: The user's group ID
	GID uint32
}

type Group struct {
	// Required: The name of the group
	GroupName string
	// Required: The group ID
	GID uint32
	// Required: The list of members of the group
	Members []string
}

type PathMutation struct {
	// The target path to mutate
	Path string
	// The type of mutation to perform
	//
	// This can be one of: directory, empty-file, hardlink, symlink, permissions
	Type string
	// The mutation's desired user ID
	UID uint32
	// The mutation's desired group ID
	GID uint32
	// The permission bits for the path
	Permissions uint32
	// The source path to mutate
	Source string
	// Toggle whether to mutate recursively
	Recursive bool
}

type OSRelease struct {
	// Optional: The name of the OS
	Name string
	// Optional: The unique identifier for the OS
	ID string
	// Optional: The unique identifier for the version of the OS
	VersionID string `yaml:"version-id"`
	// Optional: The human readable description of the OS
	PrettyName string `yaml:"pretty-name"`
	// Optional: The URL of the homepage for the OS
	HomeURL string `yaml:"home-url"`
	// Optional: The URL of the bug reporting website for the OS
	BugReportURL string `yaml:"bug-report-url"`
}

type ImageContents struct {
	// A list of apk repositories to use for pulling packages
	Repositories []string `yaml:"repositories,omitempty"`
	// A list of public keys used to verify the desired repositories
	Keyring []string `yaml:"keyring,omitempty"`
	// A list of packages to include in the image
	Packages []string `yaml:"packages,omitempty"`
}

type ImageEntrypoint struct {
	// Optional: The type of entrypoint. Only "service-bundle" is supported.
	Type string
	// Required: The command of the entrypoint
	Command string
	// Optional: The shell fragment of the entrypoint command
	ShellFragment string `yaml:"shell-fragment"`

	Services map[string]string
}

type ImageAccounts struct {
	// Required: The user to run the container as. This can be a username or UID.
	RunAs string `yaml:"run-as"`
	// Required: List of users to populate the image with
	Users []User
	// Required: List of groups to populate the image with
	Groups []Group
}

type ImageConfiguration struct {
	// Required: The apk packages in the container image
	Contents ImageContents `yaml:"contents,omitempty"`
	// Required: The entrypoint of the container image
	//
	// This typically is the path to the executable to run. Since many of
	// images do not include a shell, this should be the full path
	// to the executable.
	Entrypoint ImageEntrypoint `yaml:"entrypoint,omitempty"`
	// Optional: The command of the container image
	//
	// These are the additional arguments to pass to the entrypoint.
	Cmd string `yaml:"cmd,omitempty"`
	// Optional: The stop signal used to suspend the execution of the containers process
	StopSignal string `yaml:"stop-signal,omitempty"`
	// Optional: The working directory of the container
	WorkDir string `yaml:"work-dir,omitempty"`
	// Optional: Account configuration for the container image
	Accounts ImageAccounts `yaml:"accounts,omitempty"`
	// Optional: List of CPU architectures to build the container image for
	//
	// The list of supported architectures is: 386, amd64, arm64, arm/v6, arm/v7, ppc64le, riscv64, s390x
	Archs []Architecture `yaml:"archs,omitempty"`
	// Optional: Envionment variables to set in the container image
	Environment map[string]string `yaml:"environment,omitempty"`
	// Optional: List of paths mutations
	Paths []PathMutation `yaml:"paths,omitempty"`
	// Optional: The /etc/os-release configuration for the container image
	OSRelease OSRelease `yaml:"os-release,omitempty"`
	// Optional: The link to version control system for this container's source code
	VCSUrl string `yaml:"vcs-url,omitempty"`
	// Optional: Annotations to apply to the images manifests
	Annotations map[string]string `yaml:"annotations,omitempty"`
	// Optional: Path to a local file containing additional image configuration
	//
	// The included configuration is deep merged with the parent configuration
	Include string `yaml:"include,omitempty"`
	// Optional: A map of named build option deviations
	Options map[string]BuildOption `yaml:"options,omitempty"`
}

// Architecture represents a CPU architecture for the container image.
// TODO(kaniini): Maybe this should be its own package at this point?
type Architecture string

func (a Architecture) String() string { return string(a) }

func (a *Architecture) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var buf string
	if err := unmarshal(&buf); err != nil {
		return err
	}

	*a = ParseArchitecture(buf)
	return nil
}

var (
	_386    = Architecture("386")
	amd64   = Architecture("amd64")
	arm64   = Architecture("arm64")
	armv6   = Architecture("arm/v6")
	armv7   = Architecture("arm/v7")
	ppc64le = Architecture("ppc64le")
	riscv64 = Architecture("riscv64")
	s390x   = Architecture("s390x")
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
		return string(a)
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
		plat.Architecture = string(a)
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
		return string(a)
	}
}

func (a Architecture) ToTriplet(suffix string) string {
	switch a {
	case _386:
		return fmt.Sprintf("i486-pc-linux-%s", suffix)
	case amd64:
		return fmt.Sprintf("x86_64-pc-linux-%s", suffix)
	case arm64:
		return fmt.Sprintf("aarch64-unknown-linux-%s", suffix)
	case armv6:
		return fmt.Sprintf("arm-unknown-linux-%seabihf", suffix)
	case armv7:
		return fmt.Sprintf("armv7l-unknown-linux-%seabihf", suffix)
	case ppc64le:
		return fmt.Sprintf("powerpc64le-unknown-linux-%s", suffix)
	case s390x:
		return fmt.Sprintf("s390x-ibm-linux-%s", suffix)
	default:
		return fmt.Sprintf("%s-unknown-linux-%s", a.ToQEmu(), suffix)
	}
}

func (a Architecture) ToRustTriplet(suffix string) string {
	switch a {
	case _386:
		return fmt.Sprintf("i686-unknown-linux-%s", suffix)
	case amd64:
		return fmt.Sprintf("x86_64-unknown-linux-%s", suffix)
	case arm64:
		return fmt.Sprintf("aarch64-unknown-linux-%s", suffix)
	case armv6:
		return fmt.Sprintf("armv6-unknown-linux-%seabihf", suffix)
	case armv7:
		return fmt.Sprintf("armv7-unknown-linux-%seabihf", suffix)
	case ppc64le:
		return fmt.Sprintf("powerpc64le-unknown-linux-%s", suffix)
	case s390x:
		return fmt.Sprintf("s390x-unknown-linux-%s", suffix)
	default:
		return fmt.Sprintf("%s-unknown-linux-%s", a.ToQEmu(), suffix)
	}
}

func (a Architecture) Compatible(b Architecture) bool {
	switch b {
	case _386:
		return a == b
	case amd64:
		return a == _386 || a == b
	case arm64:
		return a == armv6 || a == armv7 || a == b
	case armv6:
		return a == b
	case armv7:
		return a == armv6 || a == b
	default:
		return false
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
	case "x86_64", "amd64":
		return amd64
	case "aarch64", "arm64":
		return arm64
	case "armhf":
		return armv6
	case "armv7":
		return armv7
	}
	return Architecture(s)
}

// ParseArchitectures parses architecture values in string form, and returns
// the equivalent slice of Architectures.
//
// apk-style arch strings (e.g., "x86_64") are converted to the OCI-style
// equivalent ("amd64"). Values are deduped, and the resulting slice is sorted
// for reproducibility.
func ParseArchitectures(in []string) []Architecture {
	if len(in) == 1 && in[0] == "all" {
		return AllArchs
	}

	if len(in) == 1 && in[0] == "host" {
		in[0] = runtime.GOARCH
	}

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
		return archs[i] < archs[j]
	})
	return archs
}
