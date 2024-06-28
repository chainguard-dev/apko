package auth

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/chainguard-dev/clog"
)

// DefaultAuthenciators is a list of authenticators that are used by default.
var DefaultAuthenciators = multiAuthenticator{EnvAuth{}, CGRAuth{}}

// Authenticator is an interface for types that can add HTTP basic auth to a
// request.
type Authenticator interface {
	AddAuth(ctx context.Context, req *http.Request)
}

// MultiAuthenticator returns an Authenticator that tries each of the given
// authenticators in order until one of them adds auth to the request.
func MultiAuthenticator(auths ...Authenticator) Authenticator { return multiAuthenticator(auths) }

type multiAuthenticator []Authenticator

func (m multiAuthenticator) AddAuth(ctx context.Context, req *http.Request) {
	for _, a := range m {
		if _, _, ok := req.BasicAuth(); ok {
			// The request has auth, so we can stop here.
			return
		}
		a.AddAuth(ctx, req)
	}
}

// EnvAuth adds HTTP basic auth to the request if the request URL matches the
// HTTP_AUTH environment variable.
type EnvAuth struct{}

func (e EnvAuth) AddAuth(_ context.Context, req *http.Request) {
	env := os.Getenv("HTTP_AUTH")
	parts := strings.Split(env, ":")
	if len(parts) != 4 || parts[0] != "basic" {
		return
	}
	if req.URL.Host == parts[1] {
		req.SetBasicAuth(parts[2], parts[3])
	}
}

// CGRAuth adds HTTP basic auth to the request if the request URL matches
// apk.cgr.dev and the chainctl command is available.
type CGRAuth struct{}

func (c CGRAuth) AddAuth(ctx context.Context, req *http.Request) {
	log := clog.FromContext(ctx)

	host := req.Host
	if host != "apk.cgr.dev" {
		return
	}

	if _, err := exec.LookPath("chainctl"); err != nil {
		log.Warnf("chainctl not found, skipping CGR auth")
		return
	}

	// TODO(jason): Don't call this more than once per minute.
	cmd := exec.CommandContext(ctx, "chainctl", "auth", "token", "--audience", host)
	out, err := cmd.Output()
	if err != nil {
		log.Warnf("Error running `chainctl auth token`: %v", err)
		return
	}
	req.SetBasicAuth("user", string(out))
}

// StaticAuth is an Authenticator that adds HTTP basic auth to the request if
// the request URL matches the given domain.
func StaticAuth(domain, user, pass string) Authenticator {
	return staticAuth{domain, user, pass}
}

type staticAuth struct{ domain, user, pass string }

func (s staticAuth) AddAuth(_ context.Context, req *http.Request) {
	if req.Host == s.domain {
		req.SetBasicAuth(s.user, s.pass)
	}
}
