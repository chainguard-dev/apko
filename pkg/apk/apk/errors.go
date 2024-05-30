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
