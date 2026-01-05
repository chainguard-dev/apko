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
	"context"
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

	"chainguard.dev/apko/internal/tarfs"
	"chainguard.dev/apko/pkg/apk/expandapk"
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

func openAPKFile(t *testing.T, filename string) (*Package, []tar.Header) {
	t.Helper()

	apkFile, err := os.Open(filename)
	require.NoError(t, err, "failed to open APK file %s", filename)
	defer apkFile.Close()

	stat, err := apkFile.Stat()
	require.NoError(t, err, "failed to stat APK file %s", filename)

	pkg, err := ParsePackage(context.Background(), apkFile, uint64(stat.Size()))
	require.NoError(t, err, "failed to parse package from %s", filename)

	apkFile.Seek(0, 0)

	split, err := expandapk.Split(apkFile)
	require.NoError(t, err, "failed to split APK %s", filename)

	var dataSection io.Reader
	switch len(split) {
	case 2:
		dataSection = split[1]
	case 3:
		dataSection = split[2]
	default:
		require.Fail(t, "unexpected number of sections in APK %s", filename)
	}

	gz, err := gzip.NewReader(dataSection)
	require.NoError(t, err, "failed to create gzip reader for data section of %s", filename)
	defer gz.Close()

	tr := tar.NewReader(gz)
	var headers []tar.Header

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err, "failed to read tar header from %s", filename)
		headers = append(headers, *header)
	}

	return pkg, headers
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

// TestAddInstalledPackage - checks result in usr/lib/apk/db/installed
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

// TestAddInstalledPackageAdded - checks return value of AddInstalledPackage
func TestAddInstalledPackageAdded(t *testing.T) {
	newPkg := &Package{
		Name:             "testpkg",
		Version:          "1.0.0",
		Arch:             "x86_64",
		Description:      "my-description",
		URL:              "https://example.com/testpkg",
		Origin:           "testpkg",
		Dependencies:     []string{"testlib"},
		RepoCommit:       "a2020bf03d408b2ef1585d7dc52c29ce88524a76",
		BuildTime:        time.Date(2025, 8, 11, 1, 0, 0, 0, time.UTC),
		Size:             13282,
		InstalledSize:    123541,
		License:          "GPL-2.0-only",
		ProviderPriority: 0,
	}
	newPkgContent := strings.Join([]string{
		"P:testpkg",
		"V:1.0.0",
		"A:x86_64",
		"L:GPL-2.0-only",
		"T:my-description",
		"o:testpkg",
		"m:",
		"U:https://example.com/testpkg",
		"D:testlib",
		"p:",
		"c:a2020bf03d408b2ef1585d7dc52c29ce88524a76",
		"i:[]",
		"t:1754874000",
		"S:13282",
		"I:123541",
		"k:0",
	}, "\n")

	cases := []struct {
		name     string
		headers  []tar.Header
		expected string
	}{
		{
			name: "files in root - should create empty F record to house R:",
			headers: []tar.Header{
				{Name: "README", Typeflag: tar.TypeReg, Mode: 0o444, Uid: 0, Gid: 0},
			},
			expected: "F:\nR:README\na:0:0:0444",
		},
		{
			name: "dir in root - should not create empty F record.",
			headers: []tar.Header{
				{Name: "my.d", Typeflag: tar.TypeDir, Mode: 0o755, Uid: 0, Gid: 0},
			},
			expected: "F:my.d",
		},
		{
			name: "files sort before dirs",
			headers: []tar.Header{
				{Name: "my.d", Typeflag: tar.TypeDir, Mode: 0755, Uid: 0, Gid: 0},
				{Name: "my.d/zfile", Typeflag: tar.TypeReg, Mode: 0644, Uid: 0, Gid: 0},
				{Name: "my.d/xfile", Typeflag: tar.TypeReg, Mode: 0644, Uid: 0, Gid: 0},
				{Name: "my.d/adir", Typeflag: tar.TypeDir, Mode: 0755, Uid: 0, Gid: 0},
			},
			expected: "F:my.d\nR:xfile\nR:zfile\nF:my.d/adir",
		},
		{
			name: "files sort before dirs",
			headers: []tar.Header{
				{Name: "my.d", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "my.d/zfile", Typeflag: tar.TypeReg, Mode: 0o644},
				{Name: "my.d/xfile", Typeflag: tar.TypeReg, Mode: 0o644},
				{Name: "my.d/adir", Typeflag: tar.TypeDir, Mode: 0o755},
			},
			expected: "F:my.d\nR:xfile\nR:zfile\nF:my.d/adir",
		},
		{
			name: "file noperm",
			headers: []tar.Header{
				{Name: "adir", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "adir/file", Typeflag: tar.TypeReg, Mode: 0o000},
			},
			expected: "F:adir\nR:file\na:0:0:0000",
		},
		{
			name: "file default perm - no a: record for 0:0 644",
			headers: []tar.Header{
				{Name: "adir", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "adir/file", Typeflag: tar.TypeReg, Mode: 0o644},
			},
			expected: "F:adir\nR:file",
		},
		{
			name: "file 0600",
			headers: []tar.Header{
				{Name: "adir", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "adir/file", Typeflag: tar.TypeReg, Mode: 0o600},
			},
			expected: "F:adir\nR:file\na:0:0:0600",
		},
		{
			name: "file 4755",
			headers: []tar.Header{
				{Name: "adir", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "adir/xxfile", Typeflag: tar.TypeReg, Mode: 0o4755},
			},
			expected: "F:adir\nR:xxfile\na:0:0:4755",
		},
		{
			name: "dir default perm - no M record expected for 0:0 0755",
			headers: []tar.Header{
				{Name: "adir", Typeflag: tar.TypeDir, Mode: 0o755},
			},
			expected: "F:adir",
		},
		{
			name: "dir 1001:0 0755 - M record required",
			headers: []tar.Header{
				{Name: "adir", Typeflag: tar.TypeDir, Mode: 0o755, Uid: 1001},
			},
			expected: "F:adir\nM:1001:0:0755",
		},
		{
			name: "dir 0:1001 0755 - M record required",
			headers: []tar.Header{
				{Name: "adir", Typeflag: tar.TypeDir, Mode: 0o755, Gid: 1001},
			},
			expected: "F:adir\nM:0:1001:0755",
		},
		{
			name: "dir 0700",
			headers: []tar.Header{
				{Name: "adir", Typeflag: tar.TypeDir, Mode: 0o700},
			},
			expected: "F:adir\nM:0:0:0700",
		},
		{
			name: "dir 2600",
			headers: []tar.Header{
				{Name: "adir", Typeflag: tar.TypeDir, Mode: 0o2600},
			},
			expected: "F:adir\nM:0:0:2600",
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			a, _, err := testGetTestAPK()
			require.NoError(t, err, "unable to initialize APK implementation")

			installedBytes, err := a.AddInstalledPackage(newPkg, tt.headers)
			require.NoError(t, err, "AddInstalledPackage should not return error")
			require.NotEmpty(t, installedBytes, "AddInstalledPackage should return non-empty bytes")
			require.Equal(t, newPkgContent+"\n"+tt.expected+"\n\n", string(installedBytes))
		})
	}
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
	tw := tar.NewWriter(&buf)
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
	tw := tar.NewWriter(&buf)
	for name, content := range scripts {
		_ = tw.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(content)),
		})
		_, _ = tw.Write(content)
	}
	tw.Close()

	// pass the controltargz to updateScriptsTar
	r := bytes.NewReader(buf.Bytes())
	fs, err := tarfs.New(r, int64(buf.Len()))
	require.NoError(t, err, "unable to create tarfs: %v", err)
	err = a.updateTriggers(pkg, fs)
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

func TestPathCompare(t *testing.T) {
	cases := []struct {
		name     string
		p1       string
		p1Dir    bool
		p2       string
		p2Dir    bool
		expected int
	}{
		{"top file equal", "a.txt", false, "a.txt", false, 0},
		{"top file greater", "b.txt", false, "a.txt", false, 1},
		{"top file less", "a.txt", false, "b.txt", false, -1},
		{"top dir  equal", "aDir", true, "aDir", true, 0},
		{"top dir  greater", "bDir", true, "aDir", true, 1},
		{"top dir  less", "aDir", true, "bDir", true, -1},
		{"top file to dir 1", "a", false, "bDir", true, -1},
		{"top file to dir 2", "b", false, "aDir", true, -1},
		{"top dir to file 1", "aDir", true, "b", false, 1},
		{"top dir to file 2", "bDir", true, "a", false, 1},
		{"diff paths file 1", "/a/file", false, "/b/file", false, -1},
		{"diff paths file 2", "/a/b/c/d/file", false, "/a/b/c/e/file", false, -1},
		{"diff paths file 3", "/a/file", false, "/a/b/c/e/file", false, -1},
		{"diff paths file 4", "/a/b/c/e/file", false, "/a/file", false, 1},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected,
				pathCompare(tt.p1, tt.p1Dir, tt.p2, tt.p2Dir))
		})
	}
}

func TestCleanTarHeaders(t *testing.T) {
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
				"etc",
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
			results := cleanTarHeaders(tt.headers)

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

func TestRemoveOrphanedEntries(t *testing.T) {
	cases := []struct {
		name     string
		headers  []tar.Header
		expected []string
	}{
		{
			name: "no orphans",
			headers: []tar.Header{
				{Name: "usr", Typeflag: tar.TypeDir},
				{Name: "usr/bin", Typeflag: tar.TypeDir},
				{Name: "usr/bin/cmd", Typeflag: tar.TypeReg},
			},
			expected: []string{"usr", "usr/bin", "usr/bin/cmd"},
		},
		{
			name: "orphaned file missing intermediate directory",
			headers: []tar.Header{
				{Name: "usr", Typeflag: tar.TypeDir},
				{Name: "usr/bin/cmd", Typeflag: tar.TypeReg}, // missing usr/bin
				{Name: "etc", Typeflag: tar.TypeDir},
				{Name: "etc/logrotate.d/file", Typeflag: tar.TypeReg}, // missing etc/logrotate.d
			},
			expected: []string{"usr", "etc"},
		},
		{
			name: "orphaned directory missing parent",
			headers: []tar.Header{
				{Name: "usr", Typeflag: tar.TypeDir},
				{Name: "usr/share/docs", Typeflag: tar.TypeDir},  // missing usr/share
				{Name: "etc/logrotate.d", Typeflag: tar.TypeDir}, // missing etc
			},
			expected: []string{"usr"},
		},
		{
			name: "trailing slashes handled correctly",
			headers: []tar.Header{
				{Name: "usr/", Typeflag: tar.TypeDir},
				{Name: "usr/bin/", Typeflag: tar.TypeDir},
				{Name: "usr/bin/cmd", Typeflag: tar.TypeReg},
			},
			expected: []string{"usr/", "usr/bin/", "usr/bin/cmd"},
		},
		{
			name: "root level files kept",
			headers: []tar.Header{
				{Name: "rootfile", Typeflag: tar.TypeReg},
				{Name: "usr", Typeflag: tar.TypeDir},
				{Name: "usr/bin/cmd", Typeflag: tar.TypeReg}, // missing usr/bin
			},
			expected: []string{"rootfile", "usr"},
		},
		{
			name:     "empty input",
			headers:  []tar.Header{},
			expected: nil,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			headersCopy := make([]tar.Header, len(tt.headers))
			copy(headersCopy, tt.headers)

			newLen := removeOrphanedEntries(headersCopy)
			results := headersCopy[:newLen]

			var resultNames []string
			for _, header := range results {
				resultNames = append(resultNames, header.Name)
			}

			assert.Equal(t, tt.expected, resultNames)
		})
	}
}

// TestAddInstalledPackageFromAPK - test AddInstalled for the full apks in tree.
func TestAddInstalledPackageFromAPK(t *testing.T) {
	cases := []struct {
		name     string
		apkFile  string
		expected string
	}{
		{
			name:    "alpine-baselayout-3.4.0-r0",
			apkFile: "testdata/alpine-317/alpine-baselayout-3.4.0-r0.apk",
			expected: `P:alpine-baselayout
V:3.2.0-r23
A:aarch64
L:GPL-2.0-only
T:Alpine base dir structure and init scripts
o:alpine-baselayout
m:Natanael Copa <ncopa@alpinelinux.org>
U:https://git.alpinelinux.org/cgit/aports/tree/main/alpine-baselayout
D:alpine-baselayout-data=3.2.0-r23 /bin/sh so:libc.musl-aarch64.so.1
p:cmd:mkmntdirs=3.2.0-r23
c:348653a9ba0701e8e968b3344e72313a9ef334e4
i:[]
t:1662926906
S:11012
I:339968
k:0
C:Q1LLq2qDNrS/qRnhxQ3hsY/sHbQnc=
F:dev
F:dev/pts
F:dev/shm
F:etc
R:motd
Z:Q1XmduVVNURHQ27TvYp1Lr5TMtFcA=
F:etc/apk
F:etc/conf.d
F:etc/crontabs
R:root
a:0:0:0600
Z:Q1vfk1apUWI4yLJGhhNRd0kJixfvY=
F:etc/init.d
F:etc/modprobe.d
R:aliases.conf
Z:Q1WUbh6TBYNVK7e4Y+uUvLs/7viqk=
R:blacklist.conf
Z:Q14TdgFHkTdt3uQC+NBtrntOnm9n4=
R:i386.conf
Z:Q1pnay/njn6ol9cCssL7KiZZ8etlc=
R:kms.conf
Z:Q1ynbLn3GYDpvajba/ldp1niayeog=
F:etc/modules-load.d
F:etc/network
F:etc/network/if-down.d
F:etc/network/if-post-down.d
F:etc/network/if-pre-up.d
F:etc/network/if-up.d
F:etc/opt
F:etc/periodic
F:etc/periodic/15min
F:etc/periodic/daily
F:etc/periodic/hourly
F:etc/periodic/monthly
F:etc/periodic/weekly
F:etc/profile.d
R:README
Z:Q135OWsCzzvnB2fmFx62kbqm1Ax1k=
R:color_prompt.sh.disabled
Z:Q11XM9mde1Z29tWMGaOkeovD/m4uU=
R:locale.sh
Z:Q1S8j+WW71mWxfVy8ythqU7HUVoBw=
F:etc/sysctl.d
F:home
F:lib
F:lib/firmware
F:lib/mdev
F:lib/modules-load.d
F:lib/sysctl.d
R:00-alpine.conf
Z:Q1HpElzW1xEgmKfERtTy7oommnq6c=
F:media
F:media/cdrom
F:media/floppy
F:media/usb
F:mnt
F:opt
F:proc
F:root
M:0:0:0700
F:run
F:sbin
R:mkmntdirs
a:0:0:0755
Z:Q1Yz4VxhO2EVju3t6SmUoDtmTSK+U=
F:srv
F:sys
F:tmp
M:0:0:1777
F:usr
F:usr/lib
F:usr/lib/modules-load.d
F:usr/local
F:usr/local/bin
F:usr/local/lib
F:usr/local/share
F:usr/sbin
F:usr/share
F:usr/share/man
F:usr/share/misc
F:var
R:run
a:0:0:0777
Z:Q11/SNZz/8cK2dSKK+cJpVrZIuF4Q=
F:var/cache
F:var/cache/misc
F:var/empty
M:0:0:0555
F:var/lib
F:var/lib/misc
F:var/local
F:var/lock
F:var/lock/subsys
F:var/log
F:var/mail
F:var/opt
F:var/spool
R:mail
a:0:0:0777
Z:Q1dzbdazYZA2nTzSIG3YyNw7d4Juc=
F:var/spool/cron
R:crontabs
a:0:0:0777
Z:Q1OFZt+ZMp7j0Gny0rqSKuWJyqYmA=
F:var/tmp
M:0:0:1777

`,
		},
		{
			name:    "hello-0.1.0-r0",
			apkFile: "testdata/hello-0.1.0-r0.apk",
			expected: `P:hello
V:0.1.0-r0
A:x86_64
L:Apache-2.0
T:just a test package
o:
m:
U:
D:busybox
p:
c:
i:[]
t:0
S:499
I:4117
k:0
C:Q1DNWZeWkviN7MJedLpYM8yBvmnGM=
F:
R:hello
a:0:0:0755
Z:Q1nbbwdPygqQMTe5HHyGayHU5yBac=

`,
		},
		{
			name:    "alpine-baselayout-3.2.0-r23",
			apkFile: "testdata/alpine-317/alpine-baselayout-3.2.0-r23.apk",
			expected: `P:alpine-baselayout
V:3.2.0-r23
A:aarch64
L:GPL-2.0-only
T:Alpine base dir structure and init scripts
o:alpine-baselayout
m:Natanael Copa <ncopa@alpinelinux.org>
U:https://git.alpinelinux.org/cgit/aports/tree/main/alpine-baselayout
D:alpine-baselayout-data=3.2.0-r23 /bin/sh so:libc.musl-aarch64.so.1
p:cmd:mkmntdirs=3.2.0-r23
c:348653a9ba0701e8e968b3344e72313a9ef334e4
i:[]
t:1662926906
S:11012
I:339968
k:0
C:Q1LLq2qDNrS/qRnhxQ3hsY/sHbQnc=
F:dev
F:dev/pts
F:dev/shm
F:etc
R:motd
Z:Q1XmduVVNURHQ27TvYp1Lr5TMtFcA=
F:etc/apk
F:etc/conf.d
F:etc/crontabs
R:root
a:0:0:0600
Z:Q1vfk1apUWI4yLJGhhNRd0kJixfvY=
F:etc/init.d
F:etc/modprobe.d
R:aliases.conf
Z:Q1WUbh6TBYNVK7e4Y+uUvLs/7viqk=
R:blacklist.conf
Z:Q14TdgFHkTdt3uQC+NBtrntOnm9n4=
R:i386.conf
Z:Q1pnay/njn6ol9cCssL7KiZZ8etlc=
R:kms.conf
Z:Q1ynbLn3GYDpvajba/ldp1niayeog=
F:etc/modules-load.d
F:etc/network
F:etc/network/if-down.d
F:etc/network/if-post-down.d
F:etc/network/if-pre-up.d
F:etc/network/if-up.d
F:etc/opt
F:etc/periodic
F:etc/periodic/15min
F:etc/periodic/daily
F:etc/periodic/hourly
F:etc/periodic/monthly
F:etc/periodic/weekly
F:etc/profile.d
R:README
Z:Q135OWsCzzvnB2fmFx62kbqm1Ax1k=
R:color_prompt.sh.disabled
Z:Q11XM9mde1Z29tWMGaOkeovD/m4uU=
R:locale.sh
Z:Q1S8j+WW71mWxfVy8ythqU7HUVoBw=
F:etc/sysctl.d
F:home
F:lib
F:lib/firmware
F:lib/mdev
F:lib/modules-load.d
F:lib/sysctl.d
R:00-alpine.conf
Z:Q1HpElzW1xEgmKfERtTy7oommnq6c=
F:media
F:media/cdrom
F:media/floppy
F:media/usb
F:mnt
F:opt
F:proc
F:root
M:0:0:0700
F:run
F:sbin
R:mkmntdirs
a:0:0:0755
Z:Q1Yz4VxhO2EVju3t6SmUoDtmTSK+U=
F:srv
F:sys
F:tmp
M:0:0:1777
F:usr
F:usr/lib
F:usr/lib/modules-load.d
F:usr/local
F:usr/local/bin
F:usr/local/lib
F:usr/local/share
F:usr/sbin
F:usr/share
F:usr/share/man
F:usr/share/misc
F:var
R:run
a:0:0:0777
Z:Q11/SNZz/8cK2dSKK+cJpVrZIuF4Q=
F:var/cache
F:var/cache/misc
F:var/empty
M:0:0:0555
F:var/lib
F:var/lib/misc
F:var/local
F:var/lock
F:var/lock/subsys
F:var/log
F:var/mail
F:var/opt
F:var/spool
R:mail
a:0:0:0777
Z:Q1dzbdazYZA2nTzSIG3YyNw7d4Juc=
F:var/spool/cron
R:crontabs
a:0:0:0777
Z:Q1OFZt+ZMp7j0Gny0rqSKuWJyqYmA=
F:var/tmp
M:0:0:1777

`,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			a, _, err := testGetTestAPK()
			require.NoError(t, err, "unable to initialize APK implementation")

			pkg, files := openAPKFile(t, tt.apkFile)

			installedBytes, err := a.AddInstalledPackage(pkg, files)
			require.NoError(t, err, "AddInstalledPackage should not return error")
			require.NotEmpty(t, installedBytes, "AddInstalledPackage should return non-empty bytes")

			installedStr := string(installedBytes)
			require.Equal(t, tt.expected, installedStr, "AddInstalledPackage output should match expected format exactly")
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

func TestParseInstalledPerms(t *testing.T) {
	cases := []struct {
		name     string
		permStr  string
		uid      int
		gid      int
		perms    int64
		errMatch string
	}{
		{"executable file", "0:0:755", 0, 0, 0755, ""},
		{"setuid executable file", "0:0:4755", 0, 0, 04755, ""},
		{"non-root owner", "1001:0:644", 1001, 0, 0644, ""},
		{"non-root group", "0:1001:644", 0, 1001, 0644, ""},
		{"other-write perm", "0:0:777", 0, 0, 0777, ""},
		{"too many tokens", "0:0:0:0", 0, 0, 0, "3 parts"},
		{"bad uid token", "a:0:777", 0, 0, 0, "invalid.*uid"},
		{"bad gid token", "0:b:7770", 0, 0, 0, "invalid.*gid"},
		{"bad perm token", "0:0:cat", 0, 0, 0, "invalid.*perms"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			uid, gid, perms, err := parseInstalledPerms(tt.permStr)
			if tt.errMatch != "" {
				require.Error(t, err, "expected error found none")
				assert.Regexp(t, tt.errMatch, err.Error(), "Error message should match the regex")
				return
			}
			assert.Equal(t, tt.uid, uid, "unexpected uid")
			assert.Equal(t, tt.gid, gid, "unexpected gid")
			assert.Equal(t, tt.perms, perms, "unexpected perms")
		})
	}
}
