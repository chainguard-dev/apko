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

package build

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	osr "github.com/dominodatalab/os-release"
	"gitlab.alpinelinux.org/alpine/go/pkg/repository"
)

// TODO(kaniini): Move most of this over to gitlab.alpinelinux.org/alpine/go.
type document struct {
	BOMFormat    string       `json:"bomFormat"`
	SpecVersion  string       `json:"specVersion"`
	Version      int          `json:"version"`
	Components   []component  `json:"components,omitempty"`
	Dependencies []dependency `json:"dependencies,omitempty"`
}

type component struct {
	BOMRef             string              `json:"bom-ref"`
	Type               string              `json:"type"`
	Name               string              `json:"name"`
	Version            string              `json:"version"`
	Description        string              `json:"description"`
	PUrl               string              `json:"purl"`
	ExternalReferences []externalReference `json:"externalReferences,omitempty"`
	Licenses           []license           `json:"licenses,omitempty"`
	Components         []component         `json:"components,omitempty"`
}

type license struct {
	Expression string `json:"expression"`
}

type externalReference struct {
	URL  string `json:"url"`
	Type string `json:"type"`
}

type dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

func bomRef(ns string, pkg *repository.Package) string {
	return fmt.Sprintf("pkg:apk/%s/%s", ns, pkg.Name)
}

func bomPurl(ns string, pkg *repository.Package) string {
	return fmt.Sprintf("pkg:apk/%s/%s@%s", ns, pkg.Name, pkg.Version)
}

func (bc *Context) GenerateSBOM() error {
	log.Printf("generating SBOM")

	installedDB, err := os.Open(filepath.Join(bc.WorkDir, "lib", "apk", "db", "installed"))
	if err != nil {
		return fmt.Errorf("unable to open APK installed db: %w", err)
	}

	// repository.ParsePackageIndex closes the file itself
	packages, err := repository.ParsePackageIndex(installedDB)
	if err != nil {
		return fmt.Errorf("unable to parse APK installed db: %w", err)
	}

	// TODO(kaniini): figure out something better to do than this
	osName := "Alpine Linux"
	osID := "alpine"
	osVersion := "Unknown"

	osReleaseData, err := os.ReadFile(filepath.Join(bc.WorkDir, "etc", "os-release"))
	if err == nil {
		info := osr.Parse(string(osReleaseData))

		osName = info.Name
		osID = info.ID
		osVersion = info.VersionID
	}

	pkgComponents := []component{}
	pkgDependencies := []dependency{}

	for _, pkg := range packages {
		// add the component
		c := component{
			BOMRef:      bomRef(osID, pkg),
			Name:        pkg.Name,
			Version:     pkg.Version,
			Description: pkg.Description,
			Licenses: []license{
				{
					Expression: pkg.License,
				},
			},
			PUrl: bomPurl(osID, pkg),
			// TODO(kaniini): Talk with CycloneDX people about adding "package" type.
			Type: "operating-system",
		}

		pkgComponents = append(pkgComponents, c)

		// walk the dependency list
		depRefs := []string{}
		for _, dep := range pkg.Dependencies {
			// TODO(kaniini): Properly handle virtual dependencies...
			if strings.ContainsRune(dep, ':') {
				continue
			}

			i := strings.IndexAny(dep, " ~<>=/!")
			if i > -1 {
				dep = dep[:i]
			}
			if dep == "" {
				continue
			}

			depRefs = append(depRefs, fmt.Sprintf("pkg:apk/%s/%s", osID, dep))
		}

		d := dependency{
			Ref:       bomRef(osID, pkg),
			DependsOn: depRefs,
		}
		pkgDependencies = append(pkgDependencies, d)
	}

	rootComponent := component{
		BOMRef:     fmt.Sprintf("pkg:apk/%s", osID),
		Name:       osName,
		Version:    osVersion,
		Type:       "operating-system",
		Components: pkgComponents,
	}

	bom := document{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.4",
		Version:      1,
		Components:   []component{rootComponent},
		Dependencies: pkgDependencies,
	}

	out, err := os.Create(bc.SBOMPath)
	if err != nil {
		return fmt.Errorf("unable to open SBOM path %s for writing: %w", bc.SBOMPath, err)
	}
	defer out.Close()

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")

	err = enc.Encode(bom)
	if err != nil {
		return fmt.Errorf("unable to encode BOM: %w", err)
	}

	return nil
}
