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

package vfs

import (
	"io"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDirFS(t *testing.T) {
	dir, err := DirFS("testdata")
	if err != nil {
		log.Fatal(err)
	}

	dentry, err := dir.ReadDir(".")
	if err != nil {
		log.Fatal(err)
	}

	assert.Equal(t, len(dentry), 1, "There should only be one directory entry")
	assert.Equal(t, dentry[0].Name(), "etc", "That directory entry should be named etc")

	dentry, err = dir.ReadDir("./etc")
	if err != nil {
		log.Fatal(err)
	}

	assert.Equal(t, len(dentry), 1, "etc/ should only have one child entry")
	assert.Equal(t, dentry[0].Name(), "motd", "That directory entry should be named motd")

	st, err := dir.Stat("./etc")
	if err != nil {
		log.Fatal(err)
	}

	assert.Equal(t, st.IsDir(), true, "etc/ is a directory")

	st, err = dir.Stat("./etc/motd")
	if err != nil {
		log.Fatal(err)
	}

	assert.Equal(t, st.IsDir(), false, "etc/motd is a normal file")

	inF, err := dir.Open("./etc/motd")
	if err != nil {
		log.Fatal(err)
	}
	defer inF.Close()

	data, err := io.ReadAll(inF)
	if err != nil {
		log.Fatal(err)
	}

	assert.Equal(t, data, []byte{'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '\n'}, "motd should return Hello world")

	otherdata, err := dir.ReadFile("./etc/motd")
	assert.Equal(t, data, otherdata, "dir.ReadFile behavior should match os.ReadFile")

	outF, err := dir.Create("./etc/motd2")
	if err != nil {
		log.Fatal(err)
	}
	defer outF.Close()
	defer dir.Remove("./etc/motd2")

	if _, err := outF.Write(data); err != nil {
		log.Fatal(err)
	}
}
