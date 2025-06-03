// Copyright 2025 Chainguard, Inc.
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

// Package version exposes apko's module version information.
package version

import (
	"runtime/debug"
	"sync"
)

var once sync.Once
var apkoVersion = "unknown"

const modulePath = "chainguard.dev/apko"

// ApkoVersion returns the version of the apko module used in the current build.
func ApkoVersion() string {
	once.Do(func() {
		bi, ok := debug.ReadBuildInfo()
		if !ok {
			return
		}

		// If apko itself (or its tests) calls version.ApkoVersion, we should report the version of the module.
		if bi.Main.Path == modulePath {
			apkoVersion = bi.Main.Version
		}

		for _, d := range bi.Deps {
			if apkoVersion == "unknown" && d.Path == modulePath {
				apkoVersion = d.Version
			}
			// In case the module is replaced, we want to report the replaced version, not the original.
			if d.Replace != nil && d.Replace.Path == modulePath {
				apkoVersion = d.Replace.Version
				break
			}
		}
	})
	return apkoVersion
}
