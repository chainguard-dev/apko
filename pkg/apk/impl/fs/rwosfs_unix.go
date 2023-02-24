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

//go:build unix
// +build unix

package fs

import (
	"encoding/binary"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

func (f *dirFS) modeCharDevice(path string, fi fs.FileInfo, mode fs.FileMode) error {
	var dev int
	sys := fi.Sys()
	st1, ok1 := sys.(*syscall.Stat_t)
	st2, ok2 := sys.(*unix.Stat_t)
	switch {
	case ok1:
		dev = int(st1.Rdev)
	case ok2:
		dev = int(st2.Rdev)
	default:
		return fmt.Errorf("unsupported type %T", sys)
	}
	return f.overrides.Mknod(path, uint32(unix.S_IFCHR|mode), dev)
}

func (f *dirFS) mknod(base, name string, mode uint32, dev int) error {
	if f.caseSensitiveOnDisk(name) {
		err := unix.Mknod(filepath.Join(f.base, name), mode, dev)
		// what if we could not create it? Just create a regular file there, and memory will override
		if err != nil {
			_ = os.WriteFile(filepath.Join(f.base, name), nil, 0)
		}
	}
	return f.overrides.Mknod(name, mode, dev)
}

func (m *memFS) mknod(path string, mode uint32, dev int) error {
	file, err := m.OpenFile(
		path,
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC,
		fs.FileMode(mode)|os.ModeCharDevice|os.ModeDevice,
	)
	if err != nil {
		return err
	}
	defer file.Close()
	// save the major and minor numbers in the file itself
	devNumbers := []uint32{unix.Major(uint64(dev)), unix.Minor(uint64(dev))}
	return binary.Write(file, binary.LittleEndian, devNumbers)
}

func (m *memFS) readnod(name string) (dev int, err error) {
	file, err := m.Open(name)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	fi, err := file.Stat()
	if err != nil {
		return 0, err
	}
	if fi.Mode()&os.ModeCharDevice != os.ModeCharDevice {
		return 0, fmt.Errorf("%s not a character device", name)
	}
	// read the major and minor numbers from the file itself
	devNumbers := make([]uint32, 2)
	if err := binary.Read(file, binary.LittleEndian, devNumbers); err != nil {
		return 0, err
	}
	return int(unix.Mkdev(devNumbers[0], devNumbers[1])), nil
}
