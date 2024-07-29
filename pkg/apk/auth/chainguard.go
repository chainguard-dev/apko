package auth

import (
	"context"
	"net/http"

	"chainguard.dev/sdk/sts"
	"google.golang.org/api/idtoken"
)

// NewChainguardIdentityAuth returns an Authenticator that authorizes
// requests as the given assumeable identity.
func NewChainguardIdentityAuth(identity string) Authenticator {
	return authenticator{
		id:  identity,
		iss: "https://issuer.enforce.dev", // TODO: make these configurable.
		aud: "https://apk.cgr.dev",
	}
}

type authenticator struct {
	id, iss, aud string
}

func (a authenticator) AddAuth(ctx context.Context, req *http.Request) error {
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
