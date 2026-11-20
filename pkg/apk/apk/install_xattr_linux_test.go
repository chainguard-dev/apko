// Copyright 2026 Chainguard, Inc.
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

//go:build linux

package apk

import (
	"archive/tar"
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
)

// TestInstallAPKFilesCapabilitySurvivesChown installs a non-root-owned file
// carrying security.capability into a DirFS that writes xattrs to disk, and
// checks the capability is still on disk afterwards. chown(2) clears it, so
// this fails if the xattr is set before the Chown. Needs root (CAP_CHOWN and
// CAP_SETFCAP).
func TestInstallAPKFilesCapabilitySurvivesChown(t *testing.T) {
	skipWithoutOwnerValidation(t)
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	// vfs_cap_data revision 2, effective, permitted = CAP_NET_BIND_SERVICE.
	capData := make([]byte, 20)
	binary.LittleEndian.PutUint32(capData[0:], 0x02000001)
	binary.LittleEndian.PutUint32(capData[4:], 1<<unix.CAP_NET_BIND_SERVICE)

	dir := t.TempDir()
	fsys := apkfs.DirFS(t.Context(), dir, apkfs.DirFSWithXattrsOnDisk())
	require.NotNil(t, fsys)
	a, err := New(t.Context(), WithFS(fsys), WithIgnoreMknodErrors(ignoreMknodErrors))
	require.NoError(t, err)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name: "ping", Typeflag: tar.TypeReg, Mode: 0o755, Uid: 1000, Gid: 1000, Size: 4,
		PAXRecords: map[string]string{xattrTarPAXRecordsPrefix + "security.capability": string(capData)},
	}))
	_, err = tw.Write([]byte("ping"))
	require.NoError(t, err)
	require.NoError(t, tw.Close())

	_, err = a.installAPKFiles(t.Context(), bytes.NewReader(buf.Bytes()), &Package{Origin: ""})
	require.NoError(t, err)

	got := make([]byte, 64)
	n, err := unix.Lgetxattr(filepath.Join(dir, "ping"), "security.capability", got)
	require.NoError(t, err, "security.capability missing on disk")
	require.Equal(t, capData, got[:n])
}
