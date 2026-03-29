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

package apk

import (
	"io"
	"net/http"

	"chainguard.dev/apko/pkg/limitio"
)

// limitedResponseTransport wraps an http.RoundTripper and limits the size of response bodies.
type limitedResponseTransport struct {
	wrapped http.RoundTripper
	maxSize int64
}

// newLimitedResponseTransport creates a new transport that limits HTTP response body sizes.
// If maxSize is -1, responses are unlimited.
// If maxSize is 0, the default DefaultHTTPResponseSize is used.
func newLimitedResponseTransport(wrapped http.RoundTripper, maxSize int64) http.RoundTripper {
	return &limitedResponseTransport{
		wrapped: wrapped,
		maxSize: maxSize,
	}
}

func (t *limitedResponseTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.wrapped.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	// Wrap the response body with a limited reader
	resp.Body = &limitedReadCloser{
		ReadCloser: resp.Body,
		limited:    limitio.NewLimitedReaderWithDefault(resp.Body, t.maxSize, DefaultHTTPResponseSize),
	}

	return resp, nil
}

// limitedReadCloser wraps a ReadCloser with size limiting.
type limitedReadCloser struct {
	io.ReadCloser
	limited io.Reader
}

func (l *limitedReadCloser) Read(p []byte) (int, error) {
	return l.limited.Read(p)
}
