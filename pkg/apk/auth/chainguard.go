package auth

import (
	"context"
	"net/http"
	"strings"

	"chainguard.dev/sdk/sts"
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

func (a authenticator) AddAuth(ctx context.Context, req *http.Request) error {
	if req.Host != strings.TrimPrefix(a.aud, "https://") {
		return nil
	}

	ts, err := idtoken.NewTokenSource(ctx, a.iss)
	if err != nil {
		return err
	}
	tok, err := ts.Token()
	if err != nil {
		return err
	}
	ctok, err := sts.Exchange(ctx, a.iss, a.aud, tok.AccessToken, sts.WithIdentity(a.id))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+ctok)
	return nil
}
