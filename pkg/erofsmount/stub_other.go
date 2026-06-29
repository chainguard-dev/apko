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

//go:build !linux

package erofsmount

import (
	"context"
	"fmt"
	"runtime"
)

// Driver, NewDriver, ResolveMode are intentionally absent on non-Linux: the
// EROFS kernel module, erofsfuse, overlayfs, and fuse-overlayfs are Linux
// concepts. Mount and Unmount return a clear error so the CLI doesn't have
// to gate at every call site.
//
// Ls and OpenLayers are cross-platform (go-erofs is pure Go).

func unsupportedOS() error {
	return fmt.Errorf("apko erofs mount/umount are only supported on Linux (running on %s)", runtime.GOOS)
}

// Mount is a no-op stub on non-Linux that returns an error.
func Mount(_ context.Context, _ Source, _ string, _ Options) (*MountState, error) {
	return nil, unsupportedOS()
}

// Unmount is a no-op stub on non-Linux that returns an error.
func Unmount(_ context.Context, _ string) error {
	return unsupportedOS()
}
