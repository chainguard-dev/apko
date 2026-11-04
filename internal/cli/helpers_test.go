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

package cli_test

import (
	"os"
	"testing"

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/apko/pkg/build"
)

// unsetSourceDateEpoch clears SOURCE_DATE_EPOCH for the duration of the
// test, so the build derives its epoch from the installed packages. The
// golden fixtures were generated this way. t.Setenv registers restoration
// of the caller's value and prevents the test from running in parallel.
func unsetSourceDateEpoch(t *testing.T) {
	t.Helper()

	t.Setenv("SOURCE_DATE_EPOCH", "")
	os.Unsetenv("SOURCE_DATE_EPOCH")
}

// withIsolatedDirs puts a build's disk cache and scratch files in per-test
// directories, ahead of opts so a test can still override them. Left to the
// defaults, the build reads and writes the user's real cache directory and
// creates an apko-temp-* directory under $TMPDIR that nothing removes.
func withIsolatedDirs(t *testing.T, opts ...build.Option) []build.Option {
	t.Helper()

	return append([]build.Option{
		build.WithCache(t.TempDir(), false, apk.NewCache(false)),
		build.WithTempDir(t.TempDir()),
	}, opts...)
}
