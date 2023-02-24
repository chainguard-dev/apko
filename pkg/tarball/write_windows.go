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

//go:build windows
// +build windows

package tarball

import "io/fs"

func hasHardlinks(fs.FileInfo) bool                    { return false }
func getInodeFromFileInfo(fs.FileInfo) (uint64, error) { return 0, nil }

func (*Context) charDevice(string, fs.FS, fs.FileInfo) (bool, uint32, uint32, error) {
	return false, 0, 0, nil
}
