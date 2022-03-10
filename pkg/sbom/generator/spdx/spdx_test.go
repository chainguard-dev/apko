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
	"os"
	"path/filepath"
	"testing"

	"chainguard.dev/apko/pkg/sbom/options"
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
	err := sx.Generate(testOpts, dir)
	require.NoError(t, err)
	require.FileExists(t, filepath.Join(dir, "sbom.spdx.json"))
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
	err := sx.Generate(testOpts, dir)
	require.NoError(t, err)
	require.FileExists(t, filepath.Join(dir, "sbom.spdx.json"))
	require.NoError(t, command.New(
		"java", "-jar", jarPath, "Verify", filepath.Join(dir, "sbom.spdx.json"),
	).RunSuccess())
}
