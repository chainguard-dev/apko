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

package types

// ListOption describes an optional deviation to a list, for example, a
// list of packages.
type ListOption struct {
	Add    []string `yaml:"add,omitempty"`
	Remove []string `yaml:"remove,omitempty"`
}

// ContentsOption describes an optional deviation to an apko environment's
// contents block.
type ContentsOption struct {
	Packages ListOption `yaml:"packages,omitempty"`
}

// AccountsOption describes an optional deviation to an apko environment's
// run-as setting.
type AccountsOption struct {
	RunAs string `yaml:"run-as,omitempty"`
}

// BuildOption describes an optional deviation to an apko environment.
type BuildOption struct {
	Contents ContentsOption `yaml:"contents,omitempty"`
	Accounts AccountsOption `yaml:"accounts,omitempty"`

	Environment map[string]string `yaml:"environment,omitempty"`

	Entrypoint ImageEntrypoint `yaml:"entrypoint,omitempty"`
	OnBuild    []string        `yaml:"on-build,omitempty"`
}

// Apply applies a patch described by a BuildOption to an apko environment.
func (bo BuildOption) Apply(ic *ImageConfiguration) error {
	lo := bo.Contents.Packages
	ic.Contents.Packages = append(ic.Contents.Packages, lo.Add...)

	for _, pkg := range lo.Remove {
		pkgList := ic.Contents.Packages

		for pos, ppkg := range pkgList {
			if pkg == ppkg {
				pkgList[pos] = pkgList[len(pkgList)-1]
				pkgList = pkgList[:len(pkgList)-1]
			}
		}

		ic.Contents.Packages = pkgList
	}

	if bo.Accounts.RunAs != "" {
		ic.Accounts.RunAs = bo.Accounts.RunAs
	}

	for k, v := range bo.Environment {
		ic.Environment[k] = v
	}

	ic.OnBuild = append(ic.OnBuild, bo.OnBuild...)

	if bo.Entrypoint.Type != "" {
		ic.Entrypoint = bo.Entrypoint
	}

	return nil
}
