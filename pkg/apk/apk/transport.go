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
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
)

type rangeRetryTransport struct {
	client *http.Client
	ctx    context.Context
}

func newRangeRetryTransport(ctx context.Context, client *http.Client) *rangeRetryTransport {
	return &rangeRetryTransport{
		client: client,
		ctx:    ctx,
	}
}

func (t *rangeRetryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r := rangeRetryReader{
		client: t.client,
		ctx:    t.ctx,
		req:    req,
	}

	return r.reset(nil)
}

type rangeRetryReader struct {
	client *http.Client
	ctx    context.Context

	req *http.Request

	body io.ReadCloser

	progress int64
	total    int64
}

func (r *rangeRetryReader) reset(oerr error) (*http.Response, error) {
	if r.body != nil {
		// Intentionally ignoring this because we no longer care about the previous body.
		_ = r.body.Close()
	}

	req := r.req.WithContext(r.ctx)

	rangeHeader := fmt.Sprintf("bytes=%d-", r.progress)
	if r.progress != 0 {
		req.Header.Set("Range", rangeHeader)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return resp, errors.Join(oerr, err)
	}

	if resp.Body == nil || resp.Body == http.NoBody {
		return resp, nil
	}

	if r.total == 0 {
		r.total = resp.ContentLength
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
		if oerr != nil {
			return resp, fmt.Errorf("retrying %w: %s %s (Range: %s): unexpected status code: %d", oerr, req.Method, req.URL.String(), rangeHeader, resp.StatusCode)
		}

		return resp, fmt.Errorf("%s %s (Range: %s): unexpected status code: %d", req.Method, req.URL.String(), rangeHeader, resp.StatusCode)
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
