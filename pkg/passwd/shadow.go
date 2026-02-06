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
	"strconv"
	"strings"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
)

// ShadowEntry describes a single line in /etc/shadow.
type ShadowEntry struct {
	UserName   string // Login name
	Password   string // Encrypted password or placeholder (!, *, !*, $6$...)
	LastChange *int64 // Days since epoch of last password change
	MinDays    *int64 // Minimum days between password changes
	MaxDays    *int64 // Maximum days before password must be changed
	WarnDays   *int64 // Warning days before password expires
	InactDays  *int64 // Days after password expires until account disabled
	ExpireDate *int64 // Days since epoch when account expires
	Reserved   string // Reserved field (usually empty)
}

// ShadowFile describes an entire /etc/shadow file's contents.
type ShadowFile struct {
	Entries []ShadowEntry
}

// ReadOrCreateShadowFile parses an /etc/shadow file into a ShadowFile.
// An empty file is created if /etc/shadow is missing.
func ReadOrCreateShadowFile(fsys apkfs.FullFS, filePath string) (ShadowFile, error) {
	sf := ShadowFile{}

	file, err := fsys.OpenFile(filePath, os.O_RDONLY|os.O_CREATE, 0o640)
	if err != nil {
		return sf, fmt.Errorf("failed to open %s: %w", filePath, err)
	}
	defer file.Close()

	if err := sf.Load(file); err != nil {
		return sf, err
	}

	return sf, nil
}

// ReadShadowFile parses an /etc/shadow file into a ShadowFile.
// If /etc/shadow is missing, returns an error
func ReadShadowFile(fsys fs.FS, filePath string) (ShadowFile, error) {
	sf := ShadowFile{}

	file, err := fsys.Open(filePath)
	if err != nil {
		return sf, fmt.Errorf("failed to open %s: %w", filePath, err)
	}
	defer file.Close()

	if err := sf.Load(file); err != nil {
		return sf, err
	}

	return sf, nil
}

// Load loads an /etc/shadow file into a ShadowFile from an io.Reader.
func (sf *ShadowFile) Load(r io.Reader) error {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		se := ShadowEntry{}

		if err := se.Parse(scanner.Text()); err != nil {
			return fmt.Errorf("unable to parse: %w", err)
		}

		sf.Entries = append(sf.Entries, se)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("unable to parse: %w", err)
	}

	return nil
}

// WriteFile writes an /etc/shadow file from a ShadowFile.
func (sf *ShadowFile) WriteFile(fsys apkfs.FullFS, filePath string) error {
	file, err := fsys.Create(filePath)
	if err != nil {
		return fmt.Errorf("unable to open %s for writing: %w", filePath, err)
	}
	defer file.Close()

	return sf.Write(file)
}

// Write writes an /etc/shadow file into an io.Writer.
func (sf *ShadowFile) Write(w io.Writer) error {
	for _, se := range sf.Entries {
		if err := se.Write(w); err != nil {
			return fmt.Errorf("unable to write shadow entry: %w", err)
		}
	}

	return nil
}

// Parse parses an /etc/shadow line into a ShadowEntry.
func (se *ShadowEntry) Parse(line string) error {
	line = strings.TrimSpace(line)

	parts := strings.Split(line, ":")
	if len(parts) != 9 {
		return fmt.Errorf("malformed line, contains %d parts, expecting 9", len(parts))
	}

	se.UserName = parts[0]
	se.Password = parts[1]

	var err error
	if se.LastChange, err = parseOptionalInt64(parts[2]); err != nil {
		return fmt.Errorf("failed to parse LastChange %s: %w", parts[2], err)
	}
	if se.MinDays, err = parseOptionalInt64(parts[3]); err != nil {
		return fmt.Errorf("failed to parse MinDays %s: %w", parts[3], err)
	}
	if se.MaxDays, err = parseOptionalInt64(parts[4]); err != nil {
		return fmt.Errorf("failed to parse MaxDays %s: %w", parts[4], err)
	}
	if se.WarnDays, err = parseOptionalInt64(parts[5]); err != nil {
		return fmt.Errorf("failed to parse WarnDays %s: %w", parts[5], err)
	}
	if se.InactDays, err = parseOptionalInt64(parts[6]); err != nil {
		return fmt.Errorf("failed to parse InactDays %s: %w", parts[6], err)
	}
	if se.ExpireDate, err = parseOptionalInt64(parts[7]); err != nil {
		return fmt.Errorf("failed to parse ExpireDate %s: %w", parts[7], err)
	}

	se.Reserved = parts[8]

	return nil
}

// Write writes an /etc/shadow line into an io.Writer.
func (se *ShadowEntry) Write(w io.Writer) error {
	_, err := fmt.Fprintf(w, "%s:%s:%s:%s:%s:%s:%s:%s:%s\n",
		se.UserName,
		se.Password,
		formatOptionalInt64(se.LastChange),
		formatOptionalInt64(se.MinDays),
		formatOptionalInt64(se.MaxDays),
		formatOptionalInt64(se.WarnDays),
		formatOptionalInt64(se.InactDays),
		formatOptionalInt64(se.ExpireDate),
		se.Reserved,
	)
	return err
}

// parseOptionalInt64 parses a string as an optional int64.
// Returns nil for empty strings, otherwise parses the value.
func parseOptionalInt64(s string) (*int64, error) {
	if s == "" {
		return nil, nil
	}

	val, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return nil, err
	}

	return &val, nil
}

// formatOptionalInt64 formats an optional int64 pointer as a string.
// Returns empty string for nil, otherwise formats the value.
func formatOptionalInt64(val *int64) string {
	if val == nil {
		return ""
	}
	return strconv.FormatInt(*val, 10)
}
