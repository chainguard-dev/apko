// Copyright 2023 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package impl

import (
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"

	apkfs "chainguard.dev/apko/pkg/apk/impl/fs"
)

type testLocalTransport struct {
	root         string
	basenameOnly bool
}

func (t *testLocalTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	var target string
	if t.basenameOnly {
		target = filepath.Join(t.root, filepath.Base(request.URL.Path))
	} else {
		target = filepath.Join(t.root, request.URL.Path)
	}
	f, err := os.Open(target)
	if err != nil {
		return &http.Response{StatusCode: 404}, nil
	}
	return &http.Response{
		StatusCode: 200,
		Body:       f,
	}, nil
}

func testGetTestAPK() (*APKImplementation, apkfs.FullFS, error) {
	// load it all into memory so that we don't change any of our test data
	src := apkfs.NewMemFS()
	filesystem := os.DirFS("testdata/root")
	if walkErr := fs.WalkDir(filesystem, ".", func(path string, d fs.DirEntry, err error) error {
		if path == "." {
			return nil
		}
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if err := src.MkdirAll(path, d.Type()); err != nil {
				return err
			}
			return nil
		}
		r, err := filesystem.Open(path)
		if err != nil {
			return err
		}
		w, err := src.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, d.Type())
		if err != nil {
			return err
		}
		_, err = io.Copy(w, r)
		return err
	}); walkErr != nil {
		return nil, nil, walkErr
	}
	apk, err := NewAPKImplementation(WithFS(src), WithIgnoreMknodErrors(ignoreMknodErrors))
	if err != nil {
		return nil, nil, err
	}
	return apk, src, err
}
