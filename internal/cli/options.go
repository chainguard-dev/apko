package cli

import "chainguard.dev/apko/pkg/log"

type publishOpt struct {
	packageVersionTag       string
	packageVersionTagStem   bool
	packageVersionTagPrefix string
	tagSuffix               string
	local                   bool
	stageTags               string
	tags                    []string
	logger                  log.Logger
}

// PublishOption is an option for publishing
type PublishOption func(*publishOpt) error

// WithPackageVersionTag sets a tag to use, e.g. `glibc-2.31`.
func WithPackageVersionTag(pvt string) PublishOption {
	return func(p *publishOpt) error {
		p.packageVersionTag = pvt
		return nil
	}
}

// WithPackageVersionTagStem sets whether to use the package version tag stem, e.g. `glibc`.
func WithPackageVersionTagStem(packageVersionTagStem bool) PublishOption {
	return func(p *publishOpt) error {
		p.packageVersionTagStem = packageVersionTagStem
		return nil
	}
}

// WithPackageVersionTagPrefix sets a tag prefix to use, e.g. `glibc-`.
func WithPackageVersionTagPrefix(packageVersionTagPrefix string) PublishOption {
	return func(p *publishOpt) error {
		p.packageVersionTagPrefix = packageVersionTagPrefix
		return nil
	}
}

// WithTagSuffix sets a tag suffix to use, e.g. `-glibc`.
func WithTagSuffix(tagSuffix string) PublishOption {
	return func(p *publishOpt) error {
		p.tagSuffix = tagSuffix
		return nil
	}
}

// WithLocal sets whether to publish image to local Docker daemon.
func WithLocal(local bool) PublishOption {
	return func(p *publishOpt) error {
		p.local = local
		return nil
	}
}

// WithStageTags prevents tagging, and innstead writes all tags to the filename provided.
func WithStageTags(stageTags string) PublishOption {
	return func(p *publishOpt) error {
		p.stageTags = stageTags
		return nil
	}
}

// WithTags tags to use
func WithTags(tags ...string) PublishOption {
	return func(p *publishOpt) error {
		p.tags = tags
		return nil
	}
}

// WithLogger logger to use
func WithLogger(logger log.Logger) PublishOption {
	return func(p *publishOpt) error {
		p.logger = logger
		return nil
	}
}
