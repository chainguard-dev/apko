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

package exec_test

import (
	"fmt"
	"io"
	"testing"

	"chainguard.dev/apko/pkg/exec"
	"chainguard.dev/apko/pkg/exec/execfakes"
	"chainguard.dev/apko/pkg/log"
)

func testLogger() log.Logger {
	return &log.Adapter{Out: io.Discard}
}

func TestExecute(t *testing.T) {
	tErr := fmt.Errorf("synthetic error")
	sut := &exec.Executor{
		Log: testLogger(),
	}
	for _, tc := range []struct {
		prepare   func(*execfakes.FakeExecutorImplementation)
		shouldErr bool
	}{
		{
			func(fei *execfakes.FakeExecutorImplementation) {
				fei.RunReturns(tErr)
			},
			true,
		},
		{
			func(fei *execfakes.FakeExecutorImplementation) {
				fei.RunReturns(nil)
			},
			false,
		},
	} {
		impl := execfakes.FakeExecutorImplementation{}
		tc.prepare(&impl)
		sut.SetImplementation(&impl)
		sut.Execute("command")
	}
}
