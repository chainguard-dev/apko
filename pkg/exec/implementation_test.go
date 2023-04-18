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

package exec

import (
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRun(t *testing.T) {
	impl := defaultBuildImplementation{}
	testCommand := "ls"
	for _, tc := range []struct {
		cmd       *exec.Cmd
		shouldErr bool
	}{
		{
			cmd:       exec.Command(testCommand, "."),
			shouldErr: false,
		},
		{
			// Start() fails because of non existing command
			cmd:       exec.Command("sldkfjlskdjflksjdf"),
			shouldErr: true,
		},
		{
			// Wait() fails because of exit code
			cmd:       exec.Command(testCommand, "sldkfjlskdjflksjdf"),
			shouldErr: true,
		},
	} {
		if _, err := exec.LookPath(testCommand); err != nil {
			t.Skipf("skipping Run test as %s executable not found", testCommand)
		}
		err := impl.Run(tc.cmd, "test", testLogger())
		if tc.shouldErr {
			require.Error(t, err, tc.cmd.String())
		}
	}
}
