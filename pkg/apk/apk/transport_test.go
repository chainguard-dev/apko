// Copyright 2023 Chainguard, Inc.
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

package apk

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"
	"testing/iotest"
)

type testReader struct {
	readers []io.Reader
	count   int
}

func (r *testReader) Read(p []byte) (int, error) {
	if r.count == len(r.readers) {
		return 0, io.EOF
	}

	n, err := r.readers[r.count].Read(p)
	if err != nil {
		r.count++
	}

	return n, err
}

func (r *testReader) Close() error {
	return nil
}

type testTransport struct {
	rc     io.ReadCloser
	resps  []*http.Response
	ranges []int
	count  int
}

func (t *testTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.count == len(t.resps) {
		return nil, fmt.Errorf("this shouldn't happen")
	}

	want := ""
	if r := t.ranges[t.count]; r != 0 {
		want = fmt.Sprintf("bytes=%d-", t.ranges[t.count])
	}
	if got := req.Header.Get("Range"); want != got {
		return nil, fmt.Errorf("wrong range, want %q, got %q", want, got)
	}
	resp := t.resps[t.count]
	if resp != nil {
		resp.Body = t.rc
	}
	t.count++
	return resp, nil
}

func cb() []byte {
	return bytes.Repeat([]byte("chainguard"), 1000)
}

func cr() io.Reader {
	return bytes.NewReader(cb())
}

func er() io.Reader {
	return iotest.ErrReader(fmt.Errorf("this is an error"))
}

func mr(rs ...io.Reader) io.Reader {
	return io.MultiReader(rs...)
}

func part() *http.Response {
	r := ok(1)
	r.StatusCode = http.StatusPartialContent

	return r
}

func ok(n int) *http.Response {
	return &http.Response{
		StatusCode:    http.StatusOK,
		ContentLength: int64(len(cb()) * n),
	}
}

func TestTransport(t *testing.T) {
	size := len(cb())

	fail := &http.Response{
		StatusCode: http.StatusInternalServerError,
	}

	redirect := &http.Response{
		StatusCode: http.StatusSeeOther,
		Header:     map[string][]string{"Location": {"foobar"}},
	}

	for _, tc := range []struct {
		name    string
		readers []io.Reader
		resps   []*http.Response
		ranges  []int
		want    io.Reader
		wantErr bool
	}{{
		name:    "normal success",
		readers: []io.Reader{mr(cr(), cr())},
		resps:   []*http.Response{ok(2)}, //nolint:bodyclose
		ranges:  []int{0, size},
		want:    mr(cr(), cr()),
	}, {
		name:    "retry error once",
		readers: []io.Reader{mr(cr(), er()), cr()},
		resps:   []*http.Response{ok(2), part()}, //nolint:bodyclose
		ranges:  []int{0, size},
		want:    mr(cr(), cr()),
	}, {
		name:    "retry error twice",
		readers: []io.Reader{mr(cr(), cr(), er()), er(), cr()},
		resps:   []*http.Response{ok(3), part(), part()}, //nolint:bodyclose
		ranges:  []int{0, size * 2, size * 2},
		want:    mr(cr(), cr(), cr()),
	}, {
		name:    "retry error thrice",
		readers: []io.Reader{mr(cr(), cr(), er()), er(), er(), cr()},
		resps:   []*http.Response{ok(3), part(), part(), part()}, //nolint:bodyclose
		ranges:  []int{0, size * 2, size * 2, size * 2},
		want:    mr(cr(), cr()),
		wantErr: true,
	}, {
		name:    "retry hits 500",
		readers: []io.Reader{mr(cr(), cr(), er())},
		resps:   []*http.Response{ok(3), fail}, //nolint:bodyclose
		ranges:  []int{0, size * 2},
		want:    mr(cr(), cr()),
		wantErr: true,
	}, {
		name:    "no partial response from server (must discard)",
		readers: []io.Reader{mr(cr(), er()), mr(cr(), cr())},
		resps:   []*http.Response{ok(2), ok(2)}, //nolint:bodyclose
		ranges:  []int{0, size},
		want:    mr(cr(), cr()),
	}, {
		name:    "redirect response from server",
		readers: []io.Reader{http.NoBody, mr(cr(), cr())},
		resps:   []*http.Response{redirect, ok(2)}, //nolint:bodyclose
		ranges:  []int{0, 0, size},
		want:    mr(cr(), cr()),
	}} {
		t.Run(tc.name, func(t *testing.T) {
			tr := &testReader{tc.readers, 0}
			tt := &testTransport{
				rc:     tr,
				resps:  tc.resps,
				ranges: tc.ranges,
			}

			client := &http.Client{
				Transport: NewRangeRetryTransport(tt),
			}

			req := &http.Request{
				URL:    &url.URL{},
				Header: map[string][]string{},
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			got, err := io.ReadAll(resp.Body)
			if err != nil && !tc.wantErr {
				t.Fatal(err)
			}

			want, err := io.ReadAll(tc.want)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(got, want) {
				t.Errorf("not equal!")
				t.Errorf("got  (%d): %s", len(got), got)
				t.Errorf("want (%d): %s", len(want), want)
			}
		})
	}
}
