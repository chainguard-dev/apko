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

package apk

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
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testInstalledPackages = []*Package{
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
	newPkg := &Package{
		Name:      "testpkg",
		Version:   "1.0.0",
		Arch:      "x86_64",
		BuildTime: time.Now(),
	}
	newFiles := []tar.Header{
		{Name: "usr", Typeflag: tar.TypeDir, Mode: 0o755},                          // standard perms should not generate extra perms line
		{Name: "usr/foo", Typeflag: tar.TypeDir, Mode: 0o700},                      // should generate extra M: perms line
		{Name: "usr/foo/testfile", Typeflag: tar.TypeReg, Size: 1234, Mode: 0o644}, // standard perms should not generate extra perms line
		{Name: "usr/foo/oddfile", Typeflag: tar.TypeReg, Size: 1234, Mode: 0o600},  // should generate extra a: perms line
		// Test that we correctly convert from hex to Q1-prefixed sum.
		{Name: "usr/foo/withchecksum", Typeflag: tar.TypeReg, Size: 1234, Mode: 0o600, PAXRecords: map[string]string{
			// A random checksum in the hex representation.
			paxRecordsChecksumKey: "91abf197227d2fe71d016f4ccb68b16c9c9b2768",
		}}, // should generate extra a: perms line
	}
	// AddInstalledPackage(pkg *Package, files []tar.Header) error
	_, err = a.AddInstalledPackage(newPkg, newFiles)
	require.NoErrorf(t, err, "unable to add installed package: %v", err)
	// check that the new packages were added
	pkgs, err := a.GetInstalled()
	require.NoError(t, err, "unable to get installed packages")
	require.Equal(t, len(testInstalledPackages)+1, len(pkgs), "expected %d packages, got %d", len(testInstalledPackages)+1, len(pkgs))
	lastPkg := pkgs[len(pkgs)-1]
	require.Equal(t, newPkg.Name, lastPkg.Name, "expected package name %s, got %s", newPkg.Name, lastPkg.Name)
	require.Equal(t, newPkg.Version, lastPkg.Version, "expected package version %s, got %s", newPkg.Version, lastPkg.Version)

	installedFile, err := a.fs.ReadFile(installedFilePath)
	require.NoError(t, err)

	// The same random checksum from before, converted to what we expect.
	want := "Z:Q1kavxlyJ9L+cdAW9My2ixbJybJ2g="
	str := string(installedFile)
	require.Contains(t, str, want)
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
	pkg := &Package{
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
	}
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, content := range scripts {
		_ = tw.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0o755,
			Size: int64(len(content)),
		})
		_, _ = tw.Write(content)
	}

	_ = tw.WriteHeader(&tar.Header{
		Name: ".PKGINFO",
		Mode: 0o644,
		Size: int64(len([]byte(pkginfo))),
	})
	_, _ = tw.Write([]byte(pkginfo))
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
		_, err = io.Copy(&buf, tr) //nolint:gosec
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
	pkg := &Package{
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
		_ = tw.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(content)),
		})
		_, _ = tw.Write(content)
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
	cksum := "Q1" + base64.StdEncoding.EncodeToString(pkg.Checksum)
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
	//nolint:forbidigo // this is a valid use case
	t.Errorf("could not find entry for checksum: %s", cksum)
}

func TestSortTarHeaders(t *testing.T) {
	cases := []struct {
		name     string
		headers  []tar.Header
		expected []string
	}{
		{
			name: "normal",
			headers: []tar.Header{
				{Name: "bin", Typeflag: tar.TypeDir},
				{Name: "usr", Typeflag: tar.TypeDir},
				{Name: "usr/etc", Typeflag: tar.TypeDir},
				{Name: "usr/bin", Typeflag: tar.TypeDir},
				{Name: "bin/ls", Typeflag: tar.TypeReg},
				{Name: "bin/busybox"},
				{Name: "etc", Typeflag: tar.TypeDir},
				{Name: "etc/logrotate.d", Typeflag: tar.TypeDir},
				{Name: "etc/logrotate.d/file", Typeflag: tar.TypeReg},
				{Name: "etc/logrotate.d/file2", Typeflag: tar.TypeReg},
				{Name: "etc/hosts", Typeflag: tar.TypeReg},
				{Name: "etc/mylaterfile", Typeflag: tar.TypeReg}, // this is particularly good for testing that it comes before logrotate.d
			},
			expected: []string{
				"bin",
				"bin/busybox",
				"bin/ls",
				"etc",
				"etc/hosts",
				"etc/mylaterfile",
				"etc/logrotate.d",
				"etc/logrotate.d/file",
				"etc/logrotate.d/file2",
				"usr",
				"usr/bin",
				"usr/etc",
			},
		},
		{
			name: "intermediate dirs in the tree should be required to preserve children",
			headers: []tar.Header{
				{Name: "usr", Typeflag: tar.TypeDir},
				{Name: "usr/bin", Typeflag: tar.TypeDir},
				{Name: "etc", Typeflag: tar.TypeDir},
				{Name: "etc/logrotate.d/file", Typeflag: tar.TypeReg},
				{Name: "usr/bin/cmd", Typeflag: tar.TypeReg},
			},
			expected: []string{
				"usr",
				"usr/bin",
				"usr/bin/cmd",
			},
		},
		{
			name: "handle Alpine-style headers (with trailing slashes)",
			headers: []tar.Header{
				{Name: "usr/", Typeflag: tar.TypeDir},
				{Name: "usr/bin/", Typeflag: tar.TypeDir},
				{Name: "usr/bin/cmd", Typeflag: tar.TypeReg},
			},
			expected: []string{
				"usr/",
				"usr/bin/",
				"usr/bin/cmd",
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			results := sortTarHeaders(tt.headers)

			var resultHeaderNames []string
			for _, header := range results {
				resultHeaderNames = append(resultHeaderNames, header.Name)
			}

			assert.Equal(t, tt.expected, resultHeaderNames)
		})
	}
}

func TestParseInstalledPackages(t *testing.T) {
	for _, c := range []struct {
		installedFile string
		errExp        string
		want          []string
	}{{
		installedFile: "wolfi-base",
		want: []string{
			"apk-tools",
			"busybox",
			"ca-certificates-bundle",
			"glibc",
			"glibc-locale-posix",
			"ld-linux",
			"libcrypt1",
			"libcrypto3",
			"libgcc",
			"libssl3",
			"libxcrypt",
			"wolfi-base",
			"wolfi-baselayout",
			"wolfi-keys",
			"zlib",
		},
	}, {
		installedFile: "redis-operator-compat",
		want: []string{
			"apk-tools",
			"busybox",
			"ca-certificates-bundle",
			"glibc",
			"glibc-locale-posix",
			"ld-linux",
			"libcrypt1",
			"libcrypto3",
			"libgcc",
			"libssl3",
			"libxcrypt",
			"redis-operator-compat",
			"wolfi-base",
			"wolfi-baselayout",
			"wolfi-keys",
			"zlib",
		},
	}, {
		installedFile: "bad-top-level-perms",
		errExp:        "M entry cannot be associated with top level dir",
		want:          []string{},
	}} {
		t.Run(c.installedFile, func(t *testing.T) {
			f, err := os.Open("testdata/installed/" + c.installedFile)
			if err != nil {
				t.Fatalf("opening installed: %v", err)
			}
			defer f.Close()

			installedPkgs, err := ParseInstalled(f)
			if c.errExp != "" {
				assert.Error(t, err, "ParseInstalledPackages(): Expected error but found none")
				if err != nil {
					assert.Contains(t, err.Error(), c.errExp)
				}
				return
			} else if err != nil {
				t.Fatalf("ParseInstalledPackages(): %v", err)
			}
			got := []string{}
			for _, i := range installedPkgs {
				got = append(got, i.Name)
			}
			sort.Strings(got)
			sort.Strings(c.want)

			if d := cmp.Diff(c.want, got); d != "" {
				t.Errorf("ParseInstalledPackages() mismatch (-want  got):\n%s", d)
			}
		})
	}
}

func TestParseInstalledFiles(t *testing.T) {
	for _, c := range []struct {
		installedFile string
		pkgName       string
		want          []string
	}{{
		installedFile: "wolfi-base",
		pkgName:       "ld-linux",
		want: []string{
			"etc",
			"etc/ld.so.conf",
			"etc/ld.so.conf.d",
			"etc/ld.so.conf.d/libc.conf",
			"usr",
			"usr/lib",
			"usr/lib/ld-linux-x86-64.so.2",
			"var",
			"var/lib",
			"var/lib/db",
			"var/lib/db/sbom",
			"var/lib/db/sbom/ld-linux-2.41-r55.spdx.json",
		},
	}, {
		installedFile: "redis-operator-compat",
		pkgName:       "redis-operator-compat",
		want: []string{
			"operator",
			"var",
			"var/lib",
			"var/lib/db",
			"var/lib/db/sbom",
			"var/lib/db/sbom/redis-operator-compat-0.21.0-r1.spdx.json",
		},
	}} {
		t.Run(c.installedFile, func(t *testing.T) {
			f, err := os.Open("testdata/installed/" + c.installedFile)
			if err != nil {
				t.Fatalf("opening installed: %v", err)
			}
			defer f.Close()

			installedPkgs, err := ParseInstalled(f)
			if err != nil {
				t.Fatalf("ParseInstalledFiles(): %v", err)
			}

			var installedPkg *InstalledPackage
			for _, i := range installedPkgs {
				if i.Name == c.pkgName {
					installedPkg = i
					break
				}
			}
			if installedPkg == nil {
				t.Fatalf("package %s not found installed in %s\n", c.pkgName, c.installedFile)
			}

			got := []string{}
			for _, i := range installedPkg.Files {
				got = append(got, i.Name)
			}
			sort.Strings(got)
			sort.Strings(c.want)

			if d := cmp.Diff(c.want, got); d != "" {
				t.Errorf("ParseInstalledFiles() mismatch (-want  got):\n%s", d)
			}
		})
	}
}
