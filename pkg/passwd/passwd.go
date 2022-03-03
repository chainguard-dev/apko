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

package passwd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"strconv"

	"github.com/pkg/errors"
)

// An UserEntry contains the parsed data from an /etc/passwd entry.
type UserEntry struct {
	UserName string
	Password string
	UID      int
	GID      int
	Info     string
	HomeDir  string
	Shell    string
}

// A UserFile contains the entries from an /etc/passwd file.
type UserFile struct {
	Entries	[]UserEntry
}

// Parse an /etc/passwd file into a UserFile.
func ReadUserFile(filePath string) (UserFile, error) {
	uf := UserFile{}

	file, err := os.Open(filePath)
	if err != nil {
		return uf, errors.Wrapf(err, "failed to open %s", filePath)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ue := UserEntry{}

		err = ue.Parse(scanner.Text())
		if err != nil {
			return uf, errors.Wrapf(err, "unable to parse %s", filePath)
		}

		uf.Entries = append(uf.Entries, ue)
	}

	if err := scanner.Err(); err != nil {
		return uf, errors.Wrapf(err, "unable to parse %s", filePath)
	}

	return uf, nil
}

// Write an /etc/passwd file from a UserFile.
func (uf *UserFile) WriteFile(filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return errors.Wrapf(err, "unable to open %s for writing", filePath)
	}
	defer file.Close()

	for _, ue := range uf.Entries {
		err = ue.Write(file)
		if err != nil {
			return errors.Wrapf(err, "unable to write passwd entry")
		}
	}

	return nil
}

// Parse an /etc/passwd line into a UserEntry.
func (ue *UserEntry) Parse(line string) error {
	line = strings.TrimSpace(line)

	parts := strings.Split(line, ":")
	if len(parts) != 7 {
		return errors.Errorf("malformed line, contains %d parts, expecting 7", len(parts))
	}

	ue.UserName = parts[0]
	ue.Password = parts[1]

	uid, err := strconv.Atoi(parts[2])
	if err != nil {
		return errors.Errorf("failed to parse UID %s", parts[2])
	}
	ue.UID = uid

	gid, err := strconv.Atoi(parts[3])
	if err != nil {
		return errors.Errorf("failed to parse GID %s", parts[3])
	}
	ue.GID = gid

	ue.Info = parts[4]
	ue.HomeDir = parts[5]
	ue.Shell = parts[6]

	return nil
}

// Write an /etc/passwd line into an io.Writer.
func (ue *UserEntry) Write(w io.Writer) error {
	_, err := fmt.Fprintf(w, "%s:%s:%d:%d:%s:%s:%s\n", ue.UserName, ue.Password, ue.UID, ue.GID, ue.Info, ue.HomeDir, ue.Shell)
	return err
}
