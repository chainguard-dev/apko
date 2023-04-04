// Copyright 2022, 2023 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build windows
// +build windows

package fs

import (
	"encoding/binary"
	"io/fs"
	"os"
)

func (f *dirFS) modeCharDevice(string, fs.FileInfo, fs.FileMode) error { return nil }

func (f *dirFS) mknod(_ string, name string, mode uint32, dev int) error {
	return f.overrides.Mknod(name, mode, dev)
}

func (m *memFS) mknod(path string, mode uint32, _ int) error {
	file, err := m.OpenFile(
		path,
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC,
		fs.FileMode(mode)|os.ModeCharDevice|os.ModeDevice,
	)
	if err != nil {
		return err
	}
	defer file.Close()
	devNumbers := []uint32{0, 0} // dev numbers aren't a thing on Windows.
	return binary.Write(file, binary.LittleEndian, devNumbers)
}

func (m *memFS) readnod(string) (int, error) { return 0, nil }
