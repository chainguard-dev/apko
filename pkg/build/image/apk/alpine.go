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

package apk

import (
	"log"
	"time"

	"chainguard.dev/apko/pkg/build/image"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/exec"
	"chainguard.dev/apko/pkg/s6"
)

type apkBuilder struct {
	WorkDir            string
	ImageConfiguration types.ImageConfiguration
	SourceDateEpoch    time.Time
	ExtraKeyFiles      []string
	ExtraRepos         []string
	executor           *exec.Executor
	Arch               types.Architecture
	Log                *log.Logger
	s6                 *s6.Context
}

type Option func(*apkBuilder)

func New(workDir string, l *log.Logger, opts ...Option) image.Builder {
	ab := &apkBuilder{
		WorkDir: workDir,
		s6:      s6.New(workDir, l),
		Log:     l,
	}

	for _, opt := range opts {
		opt(ab)
	}

	return ab
}

func WithImageConfiguration(ic types.ImageConfiguration) Option {
	return func(ab *apkBuilder) {
		ab.ImageConfiguration = ic
	}
}

func WithSourceDateEpoch(t time.Time) Option {
	return func(ab *apkBuilder) {
		ab.SourceDateEpoch = t
	}
}

func WithKeyFiles(keys ...string) Option {
	return func(ab *apkBuilder) {
		ab.ExtraKeyFiles = append(ab.ExtraKeyFiles, keys...)
	}
}

func WithExecutor(e *exec.Executor) Option {
	return func(ab *apkBuilder) {
		ab.executor = e
	}
}

func WithArch(arch types.Architecture) Option {
	return func(ab *apkBuilder) {
		ab.Arch = arch
	}
}

func WithExtraRepos(repos []string) Option {
	return func(ab *apkBuilder) {
		ab.ExtraRepos = repos
	}
}
