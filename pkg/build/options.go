// Copyright 2022, 2023 Chainguard, Inc.
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

package build

import (
	"fmt"
	"time"

	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/log"
)

// Option is an option for the build context.
type Option func(*Context) error

// WithConfig sets the image configuration for the build context.
// The image configuration is parsed from given config file.
func WithConfig(configFile string) Option {
	return func(bc *Context) error {
		bc.Options.Log.Printf("loading config file: %s", configFile)

		var ic types.ImageConfiguration
		if err := ic.Load(configFile, bc.Logger()); err != nil {
			return fmt.Errorf("failed to load image configuration: %w", err)
		}

		bc.ImageConfiguration = ic
		bc.ImageConfigFile = configFile

		return nil
	}
}

// WithTags sets the tags for the build context.
func WithTags(tags ...string) Option {
	return func(bc *Context) error {
		bc.Options.Tags = tags
		return nil
	}
}

// WithTarball sets the output path of the layer tarball.
func WithTarball(path string) Option {
	return func(bc *Context) error {
		bc.Options.TarballPath = path
		return nil
	}
}

// WithAssertions adds assertions to validate the result
// of this build context.
// Assertions are checked in parallel at the end of the
// build process.
func WithAssertions(a ...Assertion) Option {
	return func(bc *Context) error {
		bc.Assertions = append(bc.Assertions, a...)
		return nil
	}
}

// WithBuildDate sets the timestamps for the build context.
// The string is parsed according to RFC3339.
// An empty string is a special case and will default to
// the unix epoch.
func WithBuildDate(s string) Option {
	return func(bc *Context) error {
		// default to 0 for reproducibility
		if s == "" {
			bc.Options.SourceDateEpoch = time.Unix(0, 0).UTC()
			return nil
		}

		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return err
		}

		bc.Options.SourceDateEpoch = t

		return nil
	}
}

func WithSBOM(path string) Option {
	return func(bc *Context) error {
		bc.Options.SBOMPath = path
		return nil
	}
}

func WithSBOMFormats(formats []string) Option {
	return func(bc *Context) error {
		bc.Options.SBOMFormats = formats
		if len(formats) > 0 {
			bc.Options.WantSBOM = true
		}
		return nil
	}
}

func WithExtraKeys(keys []string) Option {
	return func(bc *Context) error {
		bc.Options.ExtraKeyFiles = keys
		return nil
	}
}

func WithExtraRepos(repos []string) Option {
	return func(bc *Context) error {
		bc.Options.ExtraRepos = repos
		return nil
	}
}

func WithExtraPackages(packages []string) Option {
	return func(bc *Context) error {
		bc.Options.ExtraPackages = packages
		return nil
	}
}

// WithImageConfiguration sets the ImageConfiguration object
// to use when building.
func WithImageConfiguration(ic types.ImageConfiguration) Option {
	return func(bc *Context) error {
		bc.ImageConfiguration = ic
		return nil
	}
}

// WithArch sets the architecture for the build context.
func WithArch(arch types.Architecture) Option {
	return func(bc *Context) error {
		bc.Options.Arch = arch
		return nil
	}
}

// WithDockerMediatypes determine whether to use Docker mediatypes for the build context.
func WithDockerMediatypes(useDockerMediaTypes bool) Option {
	return func(bc *Context) error {
		bc.Options.UseDockerMediaTypes = useDockerMediaTypes
		return nil
	}
}

// WithLogger sets the log.Logger implementation to be used by the build context.
func WithLogger(logger log.Logger) Option {
	return func(bc *Context) error {
		bc.Options.Log = logger
		return nil
	}
}

// WithDebugLogging sets the debug log level for the build context.
func WithDebugLogging(enable bool) Option {
	return func(bc *Context) error {
		if enable {
			bc.Options.Log.SetLevel(log.DebugLevel)
		}
		return nil
	}
}

// WithVCS enables VCS URL probing for the build context.
func WithVCS(enable bool) Option {
	return func(bc *Context) error {
		bc.Options.WithVCS = enable
		return nil
	}
}

// WithAnnotations adds annotations from commandline to those in the config.
// Commandline annotations take precedence.
func WithAnnotations(annotations map[string]string) Option {
	return func(bc *Context) error {
		for k, v := range annotations {
			bc.ImageConfiguration.Annotations[k] = v
		}
		return nil
	}
}

// WithCacheDir set the cache directory to use
func WithCacheDir(cacheDir string) Option {
	return func(bc *Context) error {
		bc.Options.CacheDir = cacheDir
		return nil
	}
}

// WithBuildOptions applies configured patches which have been requested to the ImageConfiguration.
// Deprecated: Use WithExtraPackages.
func WithBuildOptions(buildOptions []string) Option {
	return func(bc *Context) error {
		for _, opt := range buildOptions {
			if bo, ok := bc.ImageConfiguration.Options[opt]; ok { //nolint:staticcheck
				if err := bo.Apply(&bc.ImageConfiguration); err != nil {
					return err
				}
			}
		}

		return nil
	}
}
