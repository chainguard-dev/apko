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

package iocomb

import (
	"io"
	"os"
	"path/filepath"
	"strings"
)

// WriterFromTarget returns a writer given a target specification.
func WriterFromTarget(target string) (io.Writer, error) {
	switch target {
	case "builtin:stderr":
		return os.Stderr, nil
	case "builtin:stdout":
		return os.Stdout, nil
	case "builtin:discard":
		return io.Discard, nil
	default:
		if strings.Contains(target, "/") {
			parent := filepath.Dir(target)

			if err := os.MkdirAll(parent, 0o755); err != nil {
				return nil, err
			}
		}

		out, err := os.OpenFile(target, os.O_RDWR|os.O_CREATE, 0o644)
		if err != nil {
			return nil, err
		}

		return out, nil
	}
}

// Combine returns a writer which writes to multiple target specifications.
func Combine(targets []string) (io.Writer, error) {
	writers := []io.Writer{}

	if len(targets) == 1 {
		return WriterFromTarget(targets[0])
	}

	for _, target := range targets {
		writer, err := WriterFromTarget(target)
		if err != nil {
			return nil, err
		}

		writers = append(writers, writer)
	}

	return io.MultiWriter(writers...), nil
}
