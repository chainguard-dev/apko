package auth

import (
	"context"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"chainguard.dev/sdk/sts"
	"github.com/chainguard-dev/clog"
	"golang.org/x/time/rate"
	"google.golang.org/api/idtoken"
)

// NewChainguardIdentityAuth returns an Authenticator that authorizes
// requests as the given assumeable identity.
//
// The identity is a UIDP of a Chainguard Identity.
// Issuer is usually https://issuer.enforce.dev.
// Audience is usually https://apk.cgr.dev.
func NewChainguardIdentityAuth(identity, issuer, audience string) Authenticator {
	return &cgAuth{
		id:        identity,
		iss:       issuer,
		aud:       audience,
		sometimes: rate.Sometimes{Interval: 10 * time.Minute},
	}
}

type cgAuth struct {
	id, iss, aud string

	sometimes rate.Sometimes
	cgtok     string
	cgerr     error
}

func (a *cgAuth) AddAuth(ctx context.Context, req *http.Request) error {
	if a.id == "" {
		return nil
	}
	if req.Host != strings.TrimPrefix(a.aud, "https://") {
		return nil
	}

	a.sometimes.Do(func() {
		a.cgerr = nil
		ts, err := idtoken.NewTokenSource(ctx, a.iss)
		if err != nil {
			a.cgerr = fmt.Errorf("creating token source: %w", err)
			return
		}
		clog.FromContext(ctx).With("iss", a.iss, "aud", a.aud).Info("Exchanging GCP token for Chainguard identity " + a.id)
		tok, err := ts.Token()
		if err != nil {
			a.cgerr = fmt.Errorf("getting token: %w", err)
			return
		}

		ctok, err := sts.ExchangePair(ctx, a.iss, a.aud, tok.AccessToken, sts.WithIdentity(a.id))
		if err != nil {
			a.cgerr = fmt.Errorf("exchanging token: %w", err)
		}
		a.cgtok = ctok.AccessToken
	})
	if a.cgerr != nil {
		return a.cgerr
	}
	req.SetBasicAuth("user", a.cgtok)
	return nil
}

type k8sAuth struct {
	path, id, iss, aud string

	sometimes rate.Sometimes
	cgtok     string
	cgerr     error
}

// NewK8sAuth returns an Authenticator that authorizes
// requests as the given assumeable identity, given a projected K8s SA token.
//
// The token path is the path to the projected K8s SA token.
// The identity is a UIDP of a Chainguard Identity.
// Issuer is usually https://issuer.enforce.dev.
// Audience is usually https://apk.cgr.dev.
func NewK8sAuth(tokenPath, identity, issuer, audience string) Authenticator {
	return &k8sAuth{
		path:      tokenPath,
		id:        identity,
		iss:       issuer,
		aud:       audience,
		sometimes: rate.Sometimes{Interval: 10 * time.Minute},
	}
}

func (k *k8sAuth) AddAuth(ctx context.Context, req *http.Request) error {
	if k.id == "" || k.path == "" {
		return nil
	}
	if req.Host != strings.TrimPrefix(k.aud, "https://") {
		return nil
	}

	k.sometimes.Do(func() {
		k.cgerr = nil
		b, err := fs.ReadFile(os.DirFS(filepath.Dir(k.path)), filepath.Base(k.path))
		if err != nil {
			k.cgerr = fmt.Errorf("reading token: %w", err)
			return
		}
		clog.FromContext(ctx).With("iss", k.iss, "aud", k.aud).Info("Exchanging K8s token for Chainguard identity " + k.id)
		ctok, err := sts.ExchangePair(ctx, k.iss, k.aud, string(b), sts.WithIdentity(k.id))
		if err != nil {
			k.cgerr = fmt.Errorf("exchanging token: %w", err)
		}
		k.cgtok = ctok.AccessToken
	})
	if k.cgerr != nil {
		return k.cgerr
	}
	req.SetBasicAuth("user", k.cgtok)
	return nil
}
