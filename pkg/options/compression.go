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

package options

// Compression represents the compression algorithm used for image layers.
type Compression string

const (
	// Gzip is the gzip compression algorithm.
	Gzip Compression = "gzip"
	// Zstd is the zstd compression algorithm.
	Zstd Compression = "zstd"
)

// IsValid returns true if the compression algorithm is supported.
func (c Compression) IsValid() bool {
	switch c {
	case Gzip, Zstd:
		return true
	default:
		return false
	}
}

// Extension returns the file extension associated with the compression algorithm.
func (c Compression) Extension() string {
	switch c {
	case Zstd:
		return ".zst"
	case Gzip:
		return ".gz"
	default:
		return ".gz"
	}
}
