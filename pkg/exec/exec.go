// Copyright 2022 Chainguard, Inc.
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

package exec

type Executor struct {
	WorkDir  string
	UseProot bool
}

type Option func(*Executor)

func New(workDir string, opts ...Option) *Executor {
	e := &Executor{
		WorkDir: workDir,
	}

	for _, opt := range opts {
		opt(e)
	}

	return e
}

func WithProot(proot bool) Option {
	return func(e *Executor) {
		e.UseProot = proot
	}
}
