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

package spdx

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"chainguard.dev/apko/pkg/sbom/options"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"gitlab.alpinelinux.org/alpine/go/pkg/repository"
	"sigs.k8s.io/release-utils/command"
)

var testOpts = &options.Options{
	OS: struct {
		Name    string
		ID      string
		Version string
	}{
		Name:    "alpine",
		ID:      "alpine",
		Version: "3.0",
	},
	FileName: "sbom",
	Packages: []*repository.Package{
		{
			Name:        "musl",
			Version:     "1.2.2-r7",
			Arch:        "x86_64",
			Description: "the musl c library (libc) implementation",
			License:     "MIT",
			Origin:      "musl",
			Maintainer:  "Pkg Author <user@domain.com>",
			Checksum: []byte{
				0xd, 0xe6, 0xf4, 0x8c, 0xdc, 0xad, 0x92, 0xb8, 0xcf, 0x5b,
				0x83, 0x7f, 0x78, 0xa2, 0xd9, 0xe3, 0x70, 0x70, 0x3a, 0x5c,
			},
		},
	},
}

func TestGenerate(t *testing.T) {
	dir := t.TempDir()
	sx := New()
	path := filepath.Join(dir, testOpts.FileName+"."+sx.Ext())
	err := sx.Generate(testOpts, path)
	require.NoError(t, err)
	require.FileExists(t, path)
}

func TestReproducible(t *testing.T) {
	// Create two sboms based on the same input and ensure
	// they are identical
	dir := t.TempDir()
	sx := New()
	d := [][]byte{}
	for i := 0; i < 2; i++ {
		path := filepath.Join(dir, fmt.Sprintf("sbom%d.%s", i, sx.Ext()))
		require.NoError(t, sx.Generate(testOpts, path))
		require.FileExists(t, path)
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		d = append(d, data)
	}
	diff := cmp.Diff(d[0], d[1])
	require.Empty(t, diff, fmt.Sprintf("difference in expected output %s", diff))
}

// To run TestValidateSPDX, point SPDX_TOOLS_JAR to the SPDX tools
// jar file and make sure the java binary is in your path. The jar
// can be downloaded from https://github.com/spdx/tools-java
func TestValidateSPDX(t *testing.T) {
	jarPath := os.Getenv("SPDX_TOOLS_JAR")
	if jarPath == "" {
		os.Stderr.WriteString("Skipping validation, spdx tools jar not specified")
		return
	}
	dir := t.TempDir()
	sx := New()
	path := filepath.Join(dir, testOpts.FileName+"."+sx.Ext())
	err := sx.Generate(testOpts, dir)
	require.NoError(t, err)
	require.FileExists(t, path)
	require.NoError(t, command.New(
		"java", "-jar", jarPath, "Verify", path,
	).RunSuccess())
}

func TestStringToIdentifier(t *testing.T) {
	var validIDRe = regexp.MustCompile(`^[a-zA-Z0-9-.]+$`)
	for _, tc := range []string{
		"alpine",
		"kindest/node:v1.21.1",
		"v1.16.15@sha256:a89c771f7de234e6547d43695c7ab047809ffc71a0c3b65aa54eda051c45ed20",
		"k8s.gcr.io/ingress-nginx/e2e-test-runner:v20220110-gfd820db46@sha256:273f7d9b1b2297cd96b4d51600e45d932186a1cc79d00d179dfb43654112fe8f",
	} {
		fmt.Println(stringToIdentifier(tc))
		require.True(t, validIDRe.MatchString(stringToIdentifier(tc)))
	}
}
