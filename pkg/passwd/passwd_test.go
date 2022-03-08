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

func TestParser(t *testing.T) {
	uf, err := ReadOrCreateUserFile("testdata/passwd")
	if err != nil {
		t.Errorf("error while parsing; %v", err)
	}

	for _, ue := range uf.Entries {
		if ue.UID == 0 && ue.UserName != "root" {
			t.Errorf("uid 0 is not root")
		}

		if ue.UID == 65534 && ue.UserName != "nobody" {
			t.Errorf("uid 65534 is not nobody")
		}
	}
}

func TestWriter(t *testing.T) {
	uf, err := ReadOrCreateUserFile("testdata/passwd")
	if err != nil {
		t.Errorf("error while parsing; %v", err)
	}

	w := &bytes.Buffer{}
	if err := uf.Write(w); err != nil {
		t.Errorf("error while writing; %v", err)
	}

	r := bytes.NewReader(w.Bytes())
	uf2 := &UserFile{}
	uf2.Load(r)

	w2 := &bytes.Buffer{}
	if err := uf2.Write(w2); err != nil {
		t.Errorf("error while writing; %v", err)
	}

	if !bytes.Equal(w.Bytes(), w2.Bytes()) {
		t.Errorf("bytes are not equal %v %v", w.Bytes(), w2.Bytes())
	}
}
