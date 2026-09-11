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

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/tarfs"
)

// TestEmptyPreResolvedInstallsNothing: an explicitly empty pre-resolved set
// promises a zero-package install with no index consultation — it must not
// fall through to resolution. The configuration's only repository is a local
// path that cannot satisfy anything, so the control build proves resolution
// would fail, and the empty-set build succeeding proves it never resolved.
func TestEmptyPreResolvedInstallsNothing(t *testing.T) {
	ctx := t.Context()
	ic := types.ImageConfiguration{
		Contents: types.ImageContents{
			BuildRepositories: []string{"/nonexistent/pre-resolved-empty"},
			Packages:          []string{"busybox"},
		},
	}

	// Control: without the option, satisfying the world requires resolving
	// against the unreachable repository.
	control, err := New(ctx, tarfs.New(), WithImageConfiguration(ic), WithArch(types.ParseArchitecture("arm64")))
	if err != nil {
		t.Fatal(err)
	}
	if err := control.BuildImage(ctx); err == nil {
		t.Fatal("build without pre-resolved set: got = nil, wanted a resolution error")
	}

	// With an explicitly empty set — spelled nil or empty, both mean "this
	// set, which is empty" — the build installs precisely nothing and never
	// consults the repository.
	for _, contents := range [][]apk.PackageContents{nil, {}} {
		bc, err := New(ctx, tarfs.New(),
			WithImageConfiguration(ic),
			WithArch(types.ParseArchitecture("arm64")),
			WithPreResolvedPackages(contents),
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := bc.BuildImage(ctx); err != nil {
			t.Fatalf("empty pre-resolved build: %v", err)
		}
		installed, err := bc.APK().GetInstalled()
		if err != nil {
			t.Fatal(err)
		}
		if len(installed) != 0 {
			t.Errorf("installed packages: got = %d, wanted = 0", len(installed))
		}
	}
}
