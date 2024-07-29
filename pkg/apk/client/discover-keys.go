package client

import (
	"context"
	"net/http"

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/apko/pkg/apk/auth"
)

type Key = apk.Key

func DiscoverKeys(ctx context.Context, repository string, client *http.Client, auth auth.Authenticator) ([]Key, error) {
	a, err := apk.New()
	if err != nil {
		return nil, err
	}
	return a.DiscoverKeys(ctx, repository)
}
