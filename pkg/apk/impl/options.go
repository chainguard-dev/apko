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

package impl

import (
	"io"
	"runtime"

	"github.com/sirupsen/logrus"

	apkfs "chainguard.dev/apko/pkg/apk/impl/fs"
)

type opts struct {
	logger            Logger
	executor          Executor
	arch              string
	ignoreMknodErrors bool
	fs                apkfs.FullFS
	version           string
}

type Option func(*opts) error

// WithLogger logger to use. If not provided, will discard all log messages.
func WithLogger(logger Logger) Option {
	return func(o *opts) error {
		o.logger = logger
		return nil
	}
}

// WithExecutor executor to use. Not currently used.
func WithExecutor(executor Executor) Option {
	return func(o *opts) error {
		o.executor = executor
		return nil
	}
}

// WithArch sets the architecture to use. If not provided, will use the default runtime.GOARCH.
func WithArch(arch string) Option {
	return func(o *opts) error {
		o.arch = arch
		return nil
	}
}

// WithVersion sets the version to use for downloading keys and other purposes.
// If not provided, finds the latest stable.
func WithVersion(version string) Option {
	return func(o *opts) error {
		o.version = version
		return nil
	}
}

// WithIgnoreMknodErrors sets whether to ignore errors when creating device nodes. Default is false.
func WithIgnoreMknodErrors(ignore bool) Option {
	return func(o *opts) error {
		o.ignoreMknodErrors = ignore
		return nil
	}
}

// WithFS sets the filesystem to use. If not provided, will use the OS filesystem based at root /.
func WithFS(fs apkfs.FullFS) Option {
	return func(o *opts) error {
		o.fs = fs
		return nil
	}
}

func defaultOpts() *opts {
	fs := apkfs.DirFS("/")
	discardLogger := logrus.New()
	discardLogger.Out = io.Discard
	logger := discardLogger

	return &opts{
		logger:            logger,
		arch:              ArchToAPK(runtime.GOARCH),
		ignoreMknodErrors: false,
		fs:                fs,
	}
}
