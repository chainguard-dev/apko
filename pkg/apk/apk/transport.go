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
	"errors"
	"fmt"
	"io"
	"net/http"
)

type rangeRetryTransport struct {
	base http.RoundTripper
}

// NewRangeRetryTransport returns a transport that retries failed reads using HTTP Range requests.
func NewRangeRetryTransport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &rangeRetryTransport{base: base}
}

func (t *rangeRetryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r := &rangeRetryReader{
		base: t.base,
		req:  req,
	}

	return r.reset(nil)
}

type rangeRetryReader struct {
	base http.RoundTripper
	req  *http.Request

	body io.ReadCloser

	progress int64
}

func (r *rangeRetryReader) reset(oerr error) (*http.Response, error) {
	if r.body != nil {
		// Intentionally ignoring this because we no longer care about the previous body.
		_ = r.body.Close()
	}

	req := r.req.WithContext(r.req.Context())

	if r.progress != 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", r.progress))
	}

	resp, err := r.base.RoundTrip(req)
	if err != nil {
		return resp, errors.Join(oerr, err)
	}

	if resp.Body == nil || resp.Body == http.NoBody {
		return resp, nil
	}

	if resp.StatusCode == http.StatusOK {
		// If the upstream doesn't support Range requests for some reason and only returns 200,
		// we need to discard anything we've already Read().
		if r.progress != 0 {
			if _, err := io.CopyN(io.Discard, resp.Body, r.progress); err != nil {
				return resp, err
			}
		}
	} else if resp.StatusCode != http.StatusPartialContent {
		if r.progress != 0 {
			return resp, fmt.Errorf("retrying %w: %s %s (Range: %s): unexpected status code: %d", oerr, req.Method, req.URL.String(), req.Header.Get("Range"), resp.StatusCode)
		}

		return resp, fmt.Errorf("%s %s: unexpected status code: %d", req.Method, req.URL.String(), resp.StatusCode)
	}

	r.body = resp.Body
	resp.Body = r

	return resp, nil
}

func (r *rangeRetryReader) Read(p []byte) (n int, err error) {
	defer func() {
		r.progress += int64(n)
	}()

	// If Read() fails, we will reset() 2x.
	for _, retry := range []bool{true, true, false} {
		n, err = r.body.Read(p)
		if err == nil {
			break
		}

		if errors.Is(err, io.EOF) {
			break
		}

		if !retry {
			break
		}

		// Send a Range request in an attempt to save this io.Reader.
		resp, rerr := r.reset(err)
		if rerr != nil {
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
			return n, errors.Join(rerr, err)
		}
	}

	return n, err
}

func (r *rangeRetryReader) Close() error {
	if r.body == nil {
		return nil
	}

	return r.body.Close()
}
