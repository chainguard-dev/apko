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
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	"github.com/hashicorp/go-cleanhttp"

	"chainguard.dev/apko/pkg/apk/auth"
	apkfs "chainguard.dev/apko/pkg/apk/fs"
)

type opts struct {
	executor           Executor
	arch               string
	ignoreMknodErrors  bool
	fs                 apkfs.FullFS
	version            string
	cache              *cache
	noSignatureIndexes []string
	auth               auth.Authenticator
	ignoreSignatures   bool
	transport          http.RoundTripper
	packageGetter      PackageGetter
	sizeLimits         *SizeLimits
}

// SizeLimits configures maximum sizes for various APK operations.
type SizeLimits struct {
	APKIndexDecompressedMaxSize int64
	APKControlMaxSize           int64
	APKDataMaxSize              int64
	HTTPResponseMaxSize         int64
}

type Option func(*opts) error

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

// WithCache sets to use a cache directory for downloaded apk files and APKINDEX files.
// If not provided, will not cache.
//
// If offline is true, only read from the cache and do not make any network requests to
// populate it.
func WithCache(cacheDir string, offline bool, shared *Cache) Option {
	return func(o *opts) error {
		var err error
		if cacheDir == "" {
			cacheDir, err = os.UserCacheDir()
			if err != nil {
				return err
			}
			cacheDir = filepath.Join(cacheDir, "dev.chainguard.go-apk")
		} else {
			cacheDir, err = filepath.Abs(cacheDir)
			if err != nil {
				return err
			}
		}
		o.cache = &cache{
			dir:             cacheDir,
			offline:         offline,
			shared:          shared,
			resolverCache:   &resolverCache{},
			disqualifyCache: &disqualifyCache{},
		}
		return nil
	}
}

// WithIgnoreIndexSignatures sets whether to ignore repository signature verification.
// Default is false.
func WithIgnoreIndexSignatures(ignore bool) Option {
	return func(o *opts) error {
		o.ignoreSignatures = ignore
		return nil
	}
}

func WithNoSignatureIndexes(noSignatureIndex ...string) Option {
	return func(o *opts) error {
		o.noSignatureIndexes = append(o.noSignatureIndexes, noSignatureIndex...)
		return nil
	}
}

func WithAuthenticator(a auth.Authenticator) Option {
	return func(o *opts) error {
		o.auth = a
		return nil
	}
}

// WithTransport allows explicitly setting the inner HTTP transport.
func WithTransport(t http.RoundTripper) Option {
	return func(o *opts) error {
		if t != nil {
			o.transport = t
		}
		return nil
	}
}

// WithPackageGetter sets a custom PackageGetter for fetching, expanding, and caching packages.
// If not provided, a DefaultPackageGetter will be created automatically.
func WithPackageGetter(pg PackageGetter) Option {
	return func(o *opts) error {
		o.packageGetter = pg
		return nil
	}
}

// WithSizeLimits sets size limits for APK operations.
func WithSizeLimits(limits *SizeLimits) Option {
	return func(o *opts) error {
		o.sizeLimits = limits
		return nil
	}
}

func defaultOpts() *opts {
	return &opts{
		arch:              ArchToAPK(runtime.GOARCH),
		ignoreMknodErrors: false,
		auth:              auth.DefaultAuthenticators,
		transport:         cleanhttp.DefaultPooledTransport(),
	}
}
