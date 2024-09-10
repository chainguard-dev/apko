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
package apk

import (
	"bytes"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
)

const (
	testPrimaryPkgDir     = "testdata/alpine-316"
	testAlternatePkgDir   = "testdata/alpine-317"
	testRSA256IndexPkgDir = "testdata/rsa256-signed"
)

type testLocalTransport struct {
	fail             bool
	root             string
	basenameOnly     bool
	headers          map[string][]string
	requireBasicAuth bool
}

func (t *testLocalTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if t.fail {
		return &http.Response{
			StatusCode: 404,
			Body:       io.NopCloser(bytes.NewBuffer([]byte("not found"))),
		}, nil
	}
	if t.requireBasicAuth {
		if _, _, ok := request.BasicAuth(); !ok {
			return &http.Response{
				StatusCode: 401,
				Body:       io.NopCloser(bytes.NewBuffer([]byte("unauthorized"))),
			}, nil
		}
	}

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
		Header:     t.headers,
	}, nil
}

func testGetTestAPK() (*APK, apkfs.FullFS, error) {
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
			return src.MkdirAll(path, d.Type())
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
	apk, err := New(WithFS(src), WithIgnoreMknodErrors(ignoreMknodErrors))
	if err != nil {
		return nil, nil, err
	}
	return apk, src, err
}
