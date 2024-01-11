package cli

type publishOpt struct {
	local bool
	tags  []string
}

// PublishOption is an option for publishing
type PublishOption func(*publishOpt) error

// WithLocal sets whether to publish image to local Docker daemon.
func WithLocal(local bool) PublishOption {
	return func(p *publishOpt) error {
		p.local = local
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
