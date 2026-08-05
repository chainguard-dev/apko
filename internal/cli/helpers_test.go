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
