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

import (
	"encoding/base64"
	"fmt"
	"strings"

	"gitlab.alpinelinux.org/alpine/go/repository"
)

// PackageToIndex takes a Package and returns it as the string representation of lines in an index file.
func PackageToIndex(pkg *repository.Package) (out []string) {
	out = append(out, fmt.Sprintf("P:%s", pkg.Name))
	out = append(out, fmt.Sprintf("V:%s", pkg.Version))
	out = append(out, fmt.Sprintf("A:%s", pkg.Arch))
	out = append(out, fmt.Sprintf("L:%s", pkg.License))
	out = append(out, fmt.Sprintf("T:%s", pkg.Description))
	out = append(out, fmt.Sprintf("o:%s", pkg.Origin))
	out = append(out, fmt.Sprintf("m:%s", pkg.Maintainer))
	out = append(out, fmt.Sprintf("U:%s", pkg.URL))
	out = append(out, fmt.Sprintf("D:%s", strings.Join(pkg.Dependencies, " ")))
	out = append(out, fmt.Sprintf("p:%s", strings.Join(pkg.Provides, " ")))
	out = append(out, fmt.Sprintf("c:%s", pkg.RepoCommit))
	out = append(out, fmt.Sprintf("i:%s", pkg.InstallIf))
	out = append(out, fmt.Sprintf("t:%d", pkg.BuildTime.Unix()))
	out = append(out, fmt.Sprintf("S:%d", pkg.Size))
	out = append(out, fmt.Sprintf("I:%d", pkg.InstalledSize))
	out = append(out, fmt.Sprintf("k:%d", pkg.ProviderPriority))
	if len(pkg.Checksum) > 0 {
		out = append(out, fmt.Sprintf("C:Q1%s", base64.StdEncoding.EncodeToString(pkg.Checksum)))
	}

	return
}
