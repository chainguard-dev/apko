// Copyright 2022, 2023 Chainguard, Inc.
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
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/google/go-cmp/cmp"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/release-utils/command"

	"chainguard.dev/apko/pkg/apk/apk"
	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/sbom/options"
)

// TODO: clean this up and make consistent with the other test cases
var testOpts = &options.Options{
	ImageInfo: options.ImageInfo{
		Layers: []v1.Descriptor{{}},
	},
	OS: options.OSInfo{
		Name:    "unknown",
		ID:      "unknown",
		Version: "3.0",
	},
	FileName: "sbom",
	Packages: []*apk.InstalledPackage{
		{
			Package: apk.Package{
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
	},
}

// TODO: clean this up and make consistent with the other test cases
func TestGenerate(t *testing.T) {
	dir := t.TempDir()
	fsys := apkfs.NewMemFS()
	sx := New(fsys)
	path := filepath.Join(dir, testOpts.FileName+"."+sx.Ext())
	err := sx.Generate(t.Context(), testOpts, path)
	require.NoError(t, err)
	require.FileExists(t, path)
}

func TestSPDX_Generate(t *testing.T) {
	tests := []struct {
		name string
		opts *options.Options
	}{
		{
			name: "custom-license",
			opts: &options.Options{
				ImageInfo: options.ImageInfo{
					Layers: []v1.Descriptor{{}},
				},
				OS: options.OSInfo{
					Name:    "unknown",
					ID:      "unknown",
					Version: "3.0",
				},
				FileName: "sbom",
				Packages: []*apk.InstalledPackage{
					{
						Package: apk.Package{
							Name:    "font-ubuntu",
							Version: "0.869-r1",
						},
					},
				},
			},
		},
		{
			name: "no-supplier",
			opts: &options.Options{
				ImageInfo: options.ImageInfo{
					Layers: []v1.Descriptor{{}},
				},
				OS: options.OSInfo{
					Name:    "Apko Images, Plc",
					ID:      "apko-images",
					Version: "3.0",
				},
				FileName: "sbom",
				Packages: []*apk.InstalledPackage{
					{
						Package: apk.Package{
							Name:    "libattr1",
							Version: "2.5.1-r2",
						},
					},
				},
			},
		},
		{
			name: "package-deduplicating",
			opts: &options.Options{
				ImageInfo: options.ImageInfo{
					Layers: []v1.Descriptor{{}},
				},
				OS: options.OSInfo{
					Name:    "unknown",
					ID:      "unknown",
					Version: "3.0",
				},
				FileName: "sbom",
				Packages: []*apk.InstalledPackage{
					{
						Package: apk.Package{
							Name:    "logstash-8",
							Version: "8.15.3-r4",
						},
					},
					{
						Package: apk.Package{
							Name:    "logstash-8-compat",
							Version: "8.15.3-r4",
						},
					},
				},
			},
		},
		{
			name: "unbound-package-dedupe",
			opts: &options.Options{
				ImageInfo: options.ImageInfo{
					Layers: []v1.Descriptor{{}},
				},
				OS: options.OSInfo{
					Name:    "unknown",
					ID:      "unknown",
					Version: "3.0",
				},
				FileName: "sbom",
				Packages: []*apk.InstalledPackage{
					{
						Package: apk.Package{
							Name:    "unbound-libs",
							Version: "1.23.0-r0",
						},
					},
					{
						Package: apk.Package{
							Name:    "unbound",
							Version: "1.23.0-r0",
						},
					},
					{
						Package: apk.Package{
							Name:    "unbound-config",
							Version: "1.23.0-r0",
						},
					},
				},
			},
		},
		{
			name: "describes-relationship",
			opts: &options.Options{
				ImageInfo: options.ImageInfo{
					Layers: []v1.Descriptor{{}},
				},
				OS: options.OSInfo{
					Name:    "unknown",
					ID:      "unknown",
					Version: "3.0",
				},
				FileName: "sbom",
				Packages: []*apk.InstalledPackage{
					{
						Package: apk.Package{
							Name:    "test-pkg-describes",
							Version: "1.0.0-r0",
						},
					},
				},
			},
		},
		{
			name: "both-describes-methods",
			opts: &options.Options{
				ImageInfo: options.ImageInfo{
					Layers: []v1.Descriptor{{}},
				},
				OS: options.OSInfo{
					Name:    "unknown",
					ID:      "unknown",
					Version: "3.0",
				},
				FileName: "sbom",
				Packages: []*apk.InstalledPackage{
					{
						Package: apk.Package{
							Name:    "test-pkg-both",
							Version: "1.0.0-r0",
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := apkfs.NewMemFS()
			sbomDir := path.Join("var", "lib", "db", "sbom")
			err := fsys.MkdirAll(sbomDir, 0750)
			require.NoError(t, err)

			for _, apkPkg := range tt.opts.Packages {
				apkSBOMName := fmt.Sprintf("%s-%s.spdx.json", apkPkg.Name, apkPkg.Version)
				apkSBOMTestdataPath := filepath.Join("testdata", "apk_sboms", apkSBOMName)
				apkSBOMBytes, err := os.ReadFile(apkSBOMTestdataPath)
				require.NoError(t, err)

				sbomDestPath := path.Join(sbomDir, apkSBOMName)
				err = fsys.WriteFile(sbomDestPath, apkSBOMBytes, 0644)
				require.NoError(t, err)
			}

			sx := New(fsys)
			imageSBOMName := fmt.Sprintf("%s.spdx.json", tt.name)
			imageSBOMDestPath := filepath.Join(t.TempDir(), imageSBOMName)
			err = sx.Generate(t.Context(), tt.opts, imageSBOMDestPath)
			require.NoError(t, err)

			actual, err := os.ReadFile(imageSBOMDestPath)
			require.NoError(t, err)

			expectedImageSBOMPath := filepath.Join("testdata", "expected_image_sboms", imageSBOMName)
			expected, err := os.ReadFile(expectedImageSBOMPath)
			require.NoError(t, err)

			t.Run("goldenfile diff", func(t *testing.T) {
				if diff := cmp.Diff(expected, actual); diff != "" {
					t.Errorf("Unexpected image SBOM (-want, +got): \n%s", diff)
				}
			})

			t.Run("unique SPDX IDs", func(t *testing.T) {
				doc := new(Document)
				err := json.Unmarshal(actual, doc)
				if err != nil {
					t.Fatalf("unmarshalling SBOM: %v", err)
				}

				ids := make(map[string]struct{})
				for _, p := range doc.Packages {
					if _, ok := ids[p.ID]; ok {
						t.Errorf("duplicate SPDX ID found: %s", p.ID)
					}
					ids[p.ID] = struct{}{}
				}
			})
		})
	}
}

func TestReproducible(t *testing.T) {
	// Create two sboms based on the same input and ensure
	// they are identical
	dir := t.TempDir()
	fsys := apkfs.NewMemFS()
	sx := New(fsys)
	d := [][]byte{}
	for i := range 2 {
		path := filepath.Join(dir, fmt.Sprintf("sbom%d.%s", i, sx.Ext()))
		require.NoError(t, sx.Generate(t.Context(), testOpts, path))
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
	fsys := apkfs.NewMemFS()
	sx := New(fsys)
	path := filepath.Join(dir, testOpts.FileName+"."+sx.Ext())
	err := sx.Generate(t.Context(), testOpts, path)
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
		"k8s.gcr.io/ingress-nginx/e2e-test-runner:v2022, 20230110-gfd820db46@sha256:273f7d9b1b2297cd96b4d51600e45d932186a1cc79d00d179dfb43654112fe8f",
	} {
		fmt.Println(stringToIdentifier(tc))
		require.True(t, validIDRe.MatchString(stringToIdentifier(tc)))
	}
}

func TestSourcePackage(t *testing.T) {
	repo := "github.com/distroless/example.git"
	commitHash := "868f0dc23e721039f9669b56d01ea4b897f2fb24"
	vcsURL := fmt.Sprintf("git+ssh://%s@%s", repo, commitHash)
	doc := Document{}
	imagePackage := Package{
		ID: "dummy-id",
	}

	// Call the function
	addSourcePackage(vcsURL, &doc, &imagePackage, &options.Options{
		OS: options.OSInfo{
			Name: "Testing",
		},
	})

	// Verify the purl
	require.Len(t, doc.Packages[0].ExternalRefs, 1)
	require.Equal(t, doc.Packages[0].ExternalRefs[0].Category, ExtRefPackageManager)
	require.Equal(t, doc.Packages[0].ExternalRefs[0].Type, ExtRefTypePurl)
	require.Equal(
		t, doc.Packages[0].ExternalRefs[0].Locator,
		"pkg:github/distroless/example@868f0dc23e721039f9669b56d01ea4b897f2fb24",
	)

	// Verify the package is added
	require.Len(t, doc.Packages, 1)

	// Verify the fields are set
	require.Equal(t, repo, doc.Packages[0].Name)
	require.Equal(t, commitHash, doc.Packages[0].Version)
	require.NotNil(t, doc.Packages[0].Checksums)
	require.Len(t, doc.Packages[0].Checksums, 1)
	require.Equal(t, doc.Packages[0].Checksums[0].Value, commitHash)
	require.Equal(t, doc.Packages[0].Checksums[0].Algorithm, "SHA1")

	// Check the relationship is right
	require.Len(t, doc.Relationships, 1)
	require.Equal(t, "GENERATED_FROM", doc.Relationships[0].Type)
	require.Equal(t, imagePackage.ID, doc.Relationships[0].Element)
	require.Equal(t, doc.Packages[0].ID, doc.Relationships[0].Related)
}
