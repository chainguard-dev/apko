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

package passwd

import (
	"bufio"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
)

// GShadowEntry describes a single line in /etc/gshadow.
type GShadowEntry struct {
	GroupName      string   // Group name
	Password       string   // Encrypted group password or placeholder
	Administrators []string // Comma-separated list of group administrators
	Members        []string // Comma-separated list of group members
}

// GShadowFile describes an entire /etc/gshadow file's contents.
type GShadowFile struct {
	Entries []GShadowEntry
}

// ReadOrCreateGShadowFile parses an /etc/gshadow file into a GShadowFile.
// An empty file is created if /etc/gshadow is missing.
func ReadOrCreateGShadowFile(fsys apkfs.FullFS, filePath string) (GShadowFile, error) {
	gf := GShadowFile{}

	file, err := fsys.OpenFile(filePath, os.O_RDONLY|os.O_CREATE, 0o640)
	if err != nil {
		return gf, fmt.Errorf("failed to open %s: %w", filePath, err)
	}
	defer file.Close()

	if err := gf.Load(file); err != nil {
		return gf, err
	}

	return gf, nil
}

// ReadGShadowFile parses an /etc/gshadow file into a GShadowFile.
// If /etc/gshadow is missing, returns an error
func ReadGShadowFile(fsys fs.FS, filePath string) (GShadowFile, error) {
	gf := GShadowFile{}

	file, err := fsys.Open(filePath)
	if err != nil {
		return gf, fmt.Errorf("failed to open %s: %w", filePath, err)
	}
	defer file.Close()

	if err := gf.Load(file); err != nil {
		return gf, err
	}

	return gf, nil
}

// Load loads an /etc/gshadow file into a GShadowFile from an io.Reader.
func (gf *GShadowFile) Load(r io.Reader) error {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		ge := GShadowEntry{}

		if err := ge.Parse(scanner.Text()); err != nil {
			return fmt.Errorf("unable to parse: %w", err)
		}

		gf.Entries = append(gf.Entries, ge)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("unable to parse: %w", err)
	}

	return nil
}

// WriteFile writes an /etc/gshadow file from a GShadowFile.
func (gf *GShadowFile) WriteFile(fsys apkfs.FullFS, filePath string) error {
	file, err := fsys.Create(filePath)
	if err != nil {
		return fmt.Errorf("unable to open %s for writing: %w", filePath, err)
	}
	defer file.Close()

	return gf.Write(file)
}

// Write writes an /etc/gshadow file into an io.Writer.
func (gf *GShadowFile) Write(w io.Writer) error {
	for _, ge := range gf.Entries {
		if err := ge.Write(w); err != nil {
			return fmt.Errorf("unable to write gshadow entry: %w", err)
		}
	}

	return nil
}

// Parse parses an /etc/gshadow line into a GShadowEntry.
func (ge *GShadowEntry) Parse(line string) error {
	line = strings.TrimSpace(line)

	parts := strings.Split(line, ":")
	if len(parts) != 4 {
		return fmt.Errorf("malformed line, contains %d parts, expecting 4", len(parts))
	}

	ge.GroupName = parts[0]
	ge.Password = parts[1]
	ge.Administrators = strings.Split(parts[2], ",")
	ge.Members = strings.Split(parts[3], ",")

	return nil
}

// Write writes an /etc/gshadow line into an io.Writer.
func (ge *GShadowEntry) Write(w io.Writer) error {
	administrators := strings.Join(ge.Administrators, ",")
	members := strings.Join(ge.Members, ",")
	_, err := fmt.Fprintf(w, "%s:%s:%s:%s\n", ge.GroupName, ge.Password, administrators, members)
	return err
}
