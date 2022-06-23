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

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

import (
	"fmt"
	"os/exec"

	"github.com/sirupsen/logrus"
)

type Executor struct {
	impl     executorImplementation
	WorkDir  string
	UseProot bool
	UseQemu  string
	Log      *logrus.Logger
}

type Option func(*Executor) error

func New(workDir string, logger *logrus.Logger, opts ...Option) (*Executor, error) {
	e := &Executor{
		impl:    &defaultBuildImplementation{},
		WorkDir: workDir,
		Log:     logger,
	}

	for _, opt := range opts {
		if err := opt(e); err != nil {
			return nil, err
		}
	}

	return e, nil
}

func WithProot(proot bool) Option {
	return func(e *Executor) error {
		e.UseProot = proot
		return nil
	}
}

func WithQemu(qemuArch string) Option {
	return func(e *Executor) error {
		emu, err := exec.LookPath(fmt.Sprintf("qemu-%s", qemuArch))
		if err != nil {
			return fmt.Errorf("unable to find qemu emulator for %s: %w", qemuArch, err)
		}

		e.UseQemu = emu
		return nil
	}
}

func (e *Executor) SetImplementation(i executorImplementation) {
	e.impl = i
}
