// Copyright 2023 Chainguard, Inc.
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

package impl

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gitlab.alpinelinux.org/alpine/go/repository"
)

var testInstalledPackages = []*repository.Package{
	{Name: "alpine-baselayout-data", Version: "3.2.0-r22"},
	{Name: "musl", Version: "1.2.3-r0"},
	{Name: "busybox", Version: "1.35.0-r17"},
	{Name: "alpine-baselayout", Version: "3.2.0-r22"},
	{Name: "alpine-keys", Version: "2.4-r1"},
	{Name: "ca-certificates-bundle", Version: "20220614-r0"},
	{Name: "libcrypto1.1", Version: "1.1.1q-r0"},
	{Name: "libssl1.1", Version: "1.1.1q-r0"},
	{Name: "ssl_client", Version: "1.35.0-r17"},
	{Name: "zlib", Version: "1.2.12-r3"},
	{Name: "apk-tools", Version: "2.12.9-r3"},
	{Name: "scanelf", Version: "1.3.4-r0"},
	{Name: "musl-utils", Version: "1.2.3-r0"},
	{Name: "libc-utils", Version: "0.7.2-r3"},
}

func TestGetInstalled(t *testing.T) {
	a, _, err := testGetTestAPK()
	require.NoError(t, err, "unable to initialize APK implementation")
	pkgs, err := a.GetInstalled()
	require.NoError(t, err, "unable to get installed packages")
	var expected = testInstalledPackages
	require.Equal(t, len(expected), len(pkgs), "expected %d packages, got %d", len(expected), len(pkgs))
	// we probably could do a deepequal comparison, but that requires populating all of the fields.
	// this is good enough for now.
	for i, pkg := range pkgs {
		require.Equal(t, expected[i].Name, pkg.Name, "expected package %d to be named %s, got %s", i, expected[i].Name, pkg.Name)
		require.Equal(t, expected[i].Version, pkg.Version, "expected package %d to be version %s, got %s", i, expected[i].Version, pkg.Version)
	}
}

func TestAddInstalledPackage(t *testing.T) {
	a, _, err := testGetTestAPK()
	require.NoErrorf(t, err, "unable to initialize APK implementation: %v", err)
	newPkg := &repository.Package{
		Name:      "testpkg",
		Version:   "1.0.0",
		Arch:      "x86_64",
		BuildTime: time.Now(),
	}
	newFiles := []tar.Header{
		{Name: "usr/", Typeflag: tar.TypeDir, Mode: 0o755},                         // standard perms should not generate extra perms line
		{Name: "usr/foo/", Typeflag: tar.TypeDir, Mode: 0o700},                     // should generate extra M: perms line
		{Name: "usr/foo/testfile", Typeflag: tar.TypeReg, Size: 1234, Mode: 0o644}, // standard perms should not generate extra perms line
		{Name: "usr/foo/oddfile", Typeflag: tar.TypeReg, Size: 1234, Mode: 0o600},  // should generate extra a: perms line
	}
	// addInstalledPackage(pkg *repository.Package, files []tar.Header) error
	err = a.addInstalledPackage(newPkg, newFiles)
	require.NoErrorf(t, err, "unable to add installed package: %v", err)
	// check that the new packages were added
	pkgs, err := a.GetInstalled()
	require.NoError(t, err, "unable to get installed packages")
	require.Equal(t, len(testInstalledPackages)+1, len(pkgs), "expected %d packages, got %d", len(testInstalledPackages)+1, len(pkgs))
	lastPkg := pkgs[len(pkgs)-1]
	require.Equal(t, newPkg.Name, lastPkg.Name, "expected package name %s, got %s", newPkg.Name, lastPkg.Name)
	require.Equal(t, newPkg.Version, lastPkg.Version, "expected package version %s, got %s", newPkg.Version, lastPkg.Version)
}

func TestIsInstalledPackage(t *testing.T) {
	a, _, err := testGetTestAPK()
	require.NoErrorf(t, err, "unable to initialize APK implementation: %v", err)
	tests := []struct {
		name string
		is   bool
		err  error
	}{
		{"alpine-baselayout", true, nil},
		{"notreal123", false, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is, err := a.isInstalledPackage(tt.name)
			require.ErrorIs(t, err, tt.err, "expected error %v, got %v", tt.err, err)
			require.Equal(t, tt.is, is, "expected installed %v, got %v", tt.is, is)
		})
	}
}

func TestUpdateScriptsTar(t *testing.T) {
	a, _, err := testGetTestAPK()
	require.NoError(t, err, "unable to initialize APK implementation")
	// create the pkg
	randBytes := make([]byte, 32)
	_, err = rand.Read(randBytes)
	require.NoErrorf(t, err, "unable to generate random bytes: %v", err)
	pkg := &repository.Package{
		Name:     "testpkg",
		Version:  "1.0.0",
		Checksum: randBytes,
	}
	// this is not a fully valid PKGINFO file by any stretch, but for now it is sufficient
	triggers := "/bin /usr/bin /foo /bar/*"
	pkginfo := strings.Join([]string{
		fmt.Sprintf("pkgname = %s", pkg.Name),
		fmt.Sprintf("pkgver = %s", pkg.Version),
		fmt.Sprintf("triggers = %s", triggers),
	}, "\n")
	// construct the controlTarGz
	scripts := map[string][]byte{
		".pre-install":  []byte("echo 'pre install'"),
		".post-install": []byte("echo 'post install'"),
		".pre-upgrade":  []byte("echo 'pre upgrade'"),
		".post-upgrade": []byte("echo 'post upgrade'"),
		".PKGINFO":      []byte(pkginfo),
	}
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, content := range scripts {
		tw.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(content)),
		})
		tw.Write(content)
	}
	tw.Close()
	gw.Close()

	// pass the controltargz to updateScriptsTar
	r := bytes.NewReader(buf.Bytes())
	err = a.updateScriptsTar(pkg, r, nil)
	require.NoErrorf(t, err, "unable to update scripts tar: %v", err)
	expected := map[string][]byte{}
	for k, v := range scripts {
		if k == ".PKGINFO" {
			continue
		}
		expected[fmt.Sprintf("%s-%s.Q1%s%s", pkg.Name, pkg.Version, base64.StdEncoding.EncodeToString(pkg.Checksum), k)] = v
	}

	// successfully wrote it; not check that it was written correctly
	scriptsTar, err := a.readScriptsTar()
	require.NoErrorf(t, err, "unable to read scripts tar: %v", err)
	defer scriptsTar.Close()
	tr := tar.NewReader(scriptsTar)
	foundScripts := make(map[string][]byte)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err, "unable to read tar header: %v", err)
		if !strings.HasPrefix(header.Name, fmt.Sprintf("%s-%s", pkg.Name, pkg.Version)) {
			continue
		}
		var buf bytes.Buffer
		_, err = io.Copy(&buf, tr)
		require.NoError(t, err, "unable to read script %s: %v", header.Name, err)
		foundScripts[header.Name] = buf.Bytes()
	}
	// foundScripts should include everything in the controltargz *except* PKGINFO
	require.Equal(t, len(expected), len(foundScripts), "expected %d scripts, got %d", len(expected), len(foundScripts))
	for name, content := range expected {
		foundContent, ok := foundScripts[name]
		require.True(t, ok, "expected script %s, not found", name)
		require.True(t, bytes.Equal(content, foundContent), "expected script %s to be %s, got %s", name, content, foundContent)
	}
}

func TestUpdateTriggers(t *testing.T) {
	a, _, err := testGetTestAPK()
	require.NoError(t, err, "unable to initialize APK implementation")
	// create the pkg
	randBytes := make([]byte, 32)
	_, err = rand.Read(randBytes)
	require.NoErrorf(t, err, "unable to generate random bytes: %v", err)
	pkg := &repository.Package{
		Name:     "testpkg",
		Version:  "1.0.0",
		Checksum: randBytes,
	}
	// this is not a fully valid PKGINFO file by any stretch, but for now it is sufficient
	triggers := "/bin /usr/bin /foo /bar/*"
	pkginfo := strings.Join([]string{
		fmt.Sprintf("pkgname = %s", pkg.Name),
		fmt.Sprintf("pkgver = %s", pkg.Version),
		fmt.Sprintf("triggers = %s", triggers),
	}, "\n")
	// construct the controlTarGz
	scripts := map[string][]byte{
		".pre-install":  []byte("echo 'pre install'"),
		".post-install": []byte("echo 'post install'"),
		".pre-upgrade":  []byte("echo 'pre upgrade'"),
		".post-upgrade": []byte("echo 'post upgrade'"),
		".PKGINFO":      []byte(pkginfo),
	}
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, content := range scripts {
		tw.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(content)),
		})
		tw.Write(content)
	}
	tw.Close()
	gw.Close()

	// pass the controltargz to updateScriptsTar
	r := bytes.NewReader(buf.Bytes())
	err = a.updateTriggers(pkg, r)
	require.NoError(t, err, "unable to update triggers: %v", err)

	// successfully wrote it; not check that it was written correctly
	readTriggers, err := a.readTriggers()
	require.NoError(t, err, "unable to read triggers: %v", err)
	defer readTriggers.Close()
	cksum := base64.StdEncoding.EncodeToString(pkg.Checksum)
	// read every line in triggers, looking for one with our comment
	scanner := bufio.NewScanner(readTriggers)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) < 1 {
			continue
		}
		if parts[0] != cksum {
			continue
		}
		require.Equal(t, strings.Join(parts[1:], " "), triggers, "expected triggers to be %s, got %s", triggers, strings.Join(parts[1:], " "))
		return
	}
	// nolint:forbidigo // this is a valid use case
	t.Errorf("could not find entry for commit: %s", cksum)
}
