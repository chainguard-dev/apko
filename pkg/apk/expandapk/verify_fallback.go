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

//go:build !unix && !windows

package expandapk

import (
	"fmt"
	"os"
	"runtime"
)

func openNonblocking(path string) (*os.File, error) {
	return os.Open(path)
}

func clearNonblock(*os.File) error { return nil }

// anonymousFile refuses: this platform has neither a way to create a file that
// has no name nor a way to stop other processes opening one that does, so a
// private copy cannot be made and verified package data is not served.
func anonymousFile(string) (*os.File, error) {
	return nil, fmt.Errorf("private data files are not supported on %s", runtime.GOOS)
}
