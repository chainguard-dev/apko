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

// Package limitio provides size-limited I/O operations to prevent unbounded reads.
package limitio

import (
	"fmt"
	"io"
)

// SizeLimitExceededError is returned when a read exceeds its configured size limit.
type SizeLimitExceededError struct {
	Limit int64
}

func (e *SizeLimitExceededError) Error() string {
	return fmt.Sprintf("size limit exceeded: limit is %d bytes", e.Limit)
}

// LimitedReader wraps io.LimitedReader and returns a SizeLimitExceededError when the
// limit is exceeded. Unlike io.LimitedReader which returns EOF, this returns a
// specific error to indicate the limit was exceeded.
type LimitedReader struct {
	lr       *io.LimitedReader
	limit    int64 // original limit for error messages
	exceeded bool  // true if we've determined the limit was exceeded
}

// NewLimitedReader creates a new LimitedReader that will return a SizeLimitExceededError
// if more than limit bytes are read from r.
//   - If limit == -1: returns the reader unwrapped (unlimited)
func NewLimitedReader(r io.Reader, limit int64) io.Reader {
	if limit == -1 {
		return r
	}
	return &LimitedReader{
		lr:    &io.LimitedReader{R: r, N: limit},
		limit: limit,
	}
}

// NewLimitedReaderWithDefault creates a LimitedReader with special handling for default values:
//   - If limit == -1: returns the reader unwrapped (unlimited)
//   - If limit == 0: uses defaultLimit
//   - Otherwise: uses the provided limit
func NewLimitedReaderWithDefault(r io.Reader, limit, defaultLimit int64) io.Reader {
	if limit == 0 {
		limit = defaultLimit
	}
	return NewLimitedReader(r, limit)
}

func (l *LimitedReader) Read(p []byte) (n int, err error) {
	if l.exceeded {
		return 0, &SizeLimitExceededError{Limit: l.limit}
	}
	n, err = l.lr.Read(p)
	if err == io.EOF && l.lr.N <= 0 {
		// LimitedReader returns EOF when limit is reached, but we need to check
		// if there's more data available to determine if the limit was exceeded.
		// Try to read one more byte from the underlying reader.
		var buf [1]byte
		if nn, _ := l.lr.R.Read(buf[:]); nn > 0 {
			l.exceeded = true
			return n, &SizeLimitExceededError{Limit: l.limit}
		}
	}
	return n, err
}
