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
	"bytes"
	"testing"
)

func TestGroupParser(t *testing.T) {
	gf, err := ReadGroupFile("testdata/group")
	if err != nil {
		t.Errorf("error while parsing; %v", err)
	}

	for _, ge := range gf.Entries {
		if ge.GID == 0 && ge.GroupName != "root" {
			t.Errorf("gid 0 is not root")
		}

		if ge.GID == 65534 && ge.GroupName != "nobody" {
			t.Errorf("gid 65534 is not nobody")
		}
	}
}

func TestGroupWriter(t *testing.T) {
	gf, err := ReadGroupFile("testdata/group")
	if err != nil {
		t.Errorf("error while parsing; %v", err)
	}

	w := &bytes.Buffer{}
	err = gf.Write(w)
	if err != nil {
		t.Errorf("error while writing; %v", err)
	}

	r := bytes.NewReader(w.Bytes())
	gf2 := &GroupFile{}
	gf2.Load(r)

	w2 := &bytes.Buffer{}
	err = gf2.Write(w2)
	if err != nil {
		t.Errorf("error while writing; %v", err)
	}

	if !bytes.Equal(w.Bytes(), w2.Bytes()) {
		t.Errorf("bytes are not equal %v %v", w.Bytes(), w2.Bytes())
	}
}
