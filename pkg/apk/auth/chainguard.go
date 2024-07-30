package auth

import (
	"context"
	"net/http"
	"strings"
	"time"

	"chainguard.dev/sdk/sts"
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
	return authenticator{
		id:  identity,
		iss: issuer,
		aud: audience,
	}
}

type authenticator struct {
	id, iss, aud string
}

var cgSometimes = rate.Sometimes{Interval: 10 * time.Minute}
var cgtok string
var cerr error

func (a authenticator) AddAuth(ctx context.Context, req *http.Request) error {
	if req.Host != strings.TrimPrefix(a.aud, "https://") {
		return nil
	}

	cgSometimes.Do(func() {
		ts, err := idtoken.NewTokenSource(ctx, a.iss)
		if err != nil {
			cerr = err
			return
		}
		tok, err := ts.Token()
		if err != nil {
			cerr = err
			return
		}
		ctok, err := sts.Exchange(ctx, a.iss, a.aud, tok.AccessToken, sts.WithIdentity(a.id))
		if err != nil {
			cerr = err
		}
		cgtok = ctok
	})
	if cerr != nil {
		return cerr
	}
	req.Header.Set("Authorization", "Bearer "+cgtok)
	return nil
}
