// Copyright 2022 Chainguard, Inc.
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

package apk

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/options"
)

func TestSystemKeyringLocations(t *testing.T) {
	dir := t.TempDir()
	di := apkDefaultImplementation{}
	o := &options.Options{
		Log: &logrus.Logger{},
	}

	// Read the empty dir, passing only one empty location should err
	_, err := di.LoadSystemKeyring(o, dir)
	require.Error(t, err)

	// Write some dummy keyfiles
	for _, h := range []string{"4a6a0840", "5243ef4b", "5261cecb", "6165ee59", "61666e3f"} {
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, fmt.Sprintf("alpine-devel@lists.alpinelinux.org-%s.rsa.pub", h)),
			[]byte("testABC"), os.FileMode(0o644),
		))
	}

	// Add a redme file to ensure we dont read it
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "README.txt"), []byte("testABC"), os.FileMode(0o644),
	))

	// Successful read
	keyFiles, err := di.LoadSystemKeyring(o, dir)
	require.NoError(t, err)
	require.Len(t, keyFiles, 5)
	// should not take into account extraneous files
	require.NotContains(t, keyFiles, filepath.Join(dir, "README.txt"))

	// Unreadable directory should return error
	require.NoError(t, os.Chmod(dir, 0o000))
	_, err = di.LoadSystemKeyring(o, dir)
	require.Error(t, err)

	// reset permissions back to 0700 or the tmpdir won't be removed
	require.NoError(t, os.Chmod(dir, 0o700))
}

func TestInitKeyring(t *testing.T) {
	dir := t.TempDir()
	di := apkDefaultImplementation{}
	o := &options.Options{
		Log:     &logrus.Logger{},
		WorkDir: dir,
	}

	// Create an image configuration
	ic := &types.ImageConfiguration{
		Contents: struct {
			Repositories []string
			Keyring      []string
			Packages     []string
		}{},
	}

	keyPath := filepath.Join(dir, "alpine-devel@lists.alpinelinux.org-5e69ca50.rsa.pub")
	writeTestKey(t, keyPath)
	// Add a loca file and a remote key
	ic.Contents.Keyring = []string{
		keyPath, "https://alpinelinux.org/keys/alpine-devel%40lists.alpinelinux.org-4a6a0840.rsa.pub",
	}
	require.NoError(t, di.InitKeyring(o, ic))
	require.DirExists(t, filepath.Join(o.WorkDir, DefaultKeyRingPath))

	// Add an invalid file
	ic.Contents.Keyring = []string{
		"/liksdjlksdjlksjlksjdl",
	}
	require.Error(t, di.InitKeyring(o, ic))

	// Add an invalid url
	ic.Contents.Keyring = []string{
		"http://sldkjflskdjflklksdlksdlkjslk.net",
	}
	require.Error(t, di.InitKeyring(o, ic))
}

func writeTestKey(t *testing.T, path string) {
	demoKey := `-----BEGIN PUBLIC KEY-----
	MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwXEJ8uVwJPODshTkf2BH
	pH5fVVDppOa974+IQJsZDmGd3Ny0dcd+WwYUhNFUW3bAfc3/egaMWCaprfaHn+oS
	4ddbOFgbX8JCHdru/QMAAU0aEWSMybfJGA569c38fNUF/puX6XK/y0lD2SS3YQ/a
	oJ5jb5eNrQGR1HHMAd0G9WC4JeZ6WkVTkrcOw55F00aUPGEjejreXBerhTyFdabo
	dSfc1TILWIYD742Lkm82UBOPsOSdSfOdsMOOkSXxhdCJuCQQ70DHkw7Epy9r+X33
	ybI4r1cARcV75OviyhD8CFhAlapLKaYnRFqFxlA515e6h8i8ih/v3MSEW17cCK0b
	QwIDAQAB
	-----END PUBLIC KEY-----
`
	// Put a valid key in the directory
	require.NoError(t, os.WriteFile(path, []byte(demoKey), os.FileMode(0o644)))
}

func TestLoadSystemKeyring(t *testing.T) {
	di := apkDefaultImplementation{}

	dir := t.TempDir()
	o := &options.Options{
		Log:     &logrus.Logger{},
		WorkDir: dir,
	}

	// Trying to load the keyring without keys should fail
	_, err := di.LoadSystemKeyring(o, dir)
	require.Error(t, err)

	keyPath := filepath.Join(dir, "alpine-devel@lists.alpinelinux.org-5e69ca50.rsa.pub")
	writeTestKey(t, keyPath)

	_, err = di.LoadSystemKeyring(o, dir)
	require.NoError(t, err)

	// If the system keyring does not exist return
	if _, err := os.Stat(DefaultSystemKeyRingPath); err != nil {
		return
	}

	// Otherwise test running using the systen keyring
	_, err = di.LoadSystemKeyring(o)
	require.NoError(t, err, "testing loading system keyring")
}

func TestInitCreateDeviceFiles(t *testing.T) {
	// This test can only run as root because it needs to
	// create device files
	user, err := user.Current()
	require.NoError(t, err)
	if user.Uid != "0" {
		return
	}

	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, "dev"), os.FileMode(0o755)))
	err = initCreateDeviceFiles(&options.Options{WorkDir: dir, Log: &logrus.Logger{}})
	require.NoError(t, err)

	// Check the device files
	for _, f := range deviceFiles {
		stat, err := os.Stat(filepath.Join(dir, f.name))
		require.NoError(t, err)
		require.Equal(t, f.perm.Perm(), stat.Mode().Perm())
		require.Equal(t, false, stat.Mode().IsRegular())
	}
}

func TestInitCreateFileSystem(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "etc/apk/"), os.FileMode(0o755)))
	err := initCreateFileSystem(&options.Options{WorkDir: dir, Log: &logrus.Logger{}, Arch: types.ParseArchitecture("x86_64")})
	require.NoError(t, err)
	// Verify the filesystem is complete
	for _, f := range fileSystem {
		stat, err := os.Stat(filepath.Join(dir, f.name))
		require.NoError(t, err)
		require.Equal(t, f.isDir, stat.IsDir())
		require.Equal(t, f.perm.Perm(), stat.Mode().Perm(), f.name)
	}
}

func TestInitWriteScriptsTarball(t *testing.T) {
	tarPath := "lib/apk/db/scripts.tar"
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, filepath.Dir(tarPath)), os.FileMode(0o755)))
	err := initWriteScriptsTarball(&options.Options{WorkDir: dir, Log: &logrus.Logger{}})
	require.NoError(t, err)

	// Check the tarball can be read
	tf, err := os.Open(filepath.Join(dir, tarPath))
	require.NoError(t, err)
	tr := tar.NewReader(tf)
	_, err = tr.Next()
	require.Equal(t, io.EOF, err)
}
