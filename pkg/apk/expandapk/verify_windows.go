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

//go:build windows

package expandapk

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// openNonblocking opens path read-only. Windows has no FIFOs in the file
// namespace (named pipes live under \\.\pipe\), so a plain open cannot be made
// to block the way the unix one can.
func openNonblocking(path string) (*os.File, error) {
	return os.Open(path)
}

func clearNonblock(*os.File) error { return nil }

// anonymousFile creates a file in dir that nothing else can read or write
// while the returned descriptor is open.
//
// Windows cannot unlink a file that is open, so the unix approach of removing
// the name is not available. Instead the file is opened with no sharing at all
// (share mode 0): while this handle is open, every other attempt to open the
// file for reading, writing or deletion fails with a sharing violation, under
// any name, because sharing is enforced on the file rather than on the path.
// CREATE_NEW refuses a name that already exists, so the handle cannot land on a
// file somebody planted, and FILE_FLAG_DELETE_ON_CLOSE removes the file when the
// handle is closed, including when the process dies.
//
// What is weaker than Linux: the name is visible in dir until the handle is
// closed, and creating a hard link only needs attribute access, which share
// mode does not govern. A second name made that way cannot be opened for data
// while this handle is open, so it cannot change what is served; it does keep
// the bytes on disk after this handle closes, which matters for disclosure, not
// integrity.
func anonymousFile(dir string) (*os.File, error) {
	var rnd [16]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, err
	}
	name := filepath.Join(dir, ".apko-data-"+hex.EncodeToString(rnd[:]))

	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p,
		windows.GENERIC_READ|windows.GENERIC_WRITE|windows.DELETE,
		0, // no sharing: nobody else can open it while we hold it
		nil,
		windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_TEMPORARY|windows.FILE_FLAG_DELETE_ON_CLOSE,
		0)
	if err != nil {
		return nil, fmt.Errorf("creating %q: %w", name, err)
	}
	return os.NewFile(uintptr(h), name), nil
}
