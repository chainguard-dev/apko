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
)

type FileExistsError struct {
	Path string
	Sha1 []byte
}

func (f FileExistsError) Error() string {
	return fmt.Sprintf("file %s already exists", f.Path)
}

func (f FileExistsError) Is(target error) bool {
	var targetError FileExistsError
	return errors.As(target, &targetError)
}

// FileConflictError is returned when a file has conflicting origins.
//
// Generally, this is a user Config error. However, since this can happen
// both during Config resolution, and building - it is hard for users using
// chainguard.dev/apko as a library to flag this to the user as a user error.
//
// To help with that, we create this structure error.
type FileConflictError struct {
	// The full path of the file that has conflicting origins.
	Path string

	// The origins of the file, as a map from the package name to the origin
	Origins map[string]string
}

func (f FileConflictError) Error() string {
	return fmt.Sprintf("file %s has conflicting origins: %v", f.Path, f.Origins)
}

func (f FileConflictError) Is(target error) bool {
	var targetError FileConflictError
	return errors.As(target, &targetError)
}
