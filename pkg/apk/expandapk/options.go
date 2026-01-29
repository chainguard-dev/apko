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

package expandapk

// DefaultMaxControlSize is the default maximum decompressed size for control sections (10 MB).
const DefaultMaxControlSize int64 = 10 << 20

// DefaultMaxDataSize is the default maximum decompressed size for data sections (4 GB).
const DefaultMaxDataSize int64 = 4 << 30

// Options configures the behavior of APK expansion operations.
type Options struct {
	// MaxControlSize is the maximum decompressed size for signature and control sections.
	// Use -1 for unlimited.
	MaxControlSize int64

	// MaxDataSize is the maximum decompressed size for the data section.
	// Use -1 for unlimited.
	MaxDataSize int64
}

// Option is a functional option for configuring Options.
type Option func(*Options) error

// WithMaxControlSize sets the maximum decompressed size for signature and control sections.
func WithMaxControlSize(size int64) Option {
	return func(o *Options) error {
		o.MaxControlSize = size
		return nil
	}
}

// WithMaxDataSize sets the maximum decompressed size for the data section.
func WithMaxDataSize(size int64) Option {
	return func(o *Options) error {
		o.MaxDataSize = size
		return nil
	}
}

// DefaultOptions returns Options with default size limits.
func DefaultOptions() *Options {
	return &Options{
		MaxControlSize: DefaultMaxControlSize,
		MaxDataSize:    DefaultMaxDataSize,
	}
}
