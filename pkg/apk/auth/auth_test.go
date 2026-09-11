package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

type successAuth struct{}

func (s successAuth) AddAuth(_ context.Context, req *http.Request) error {
	req.SetBasicAuth("user", "pass")
	return nil
}

type failAuth struct{}

func (f failAuth) AddAuth(_ context.Context, req *http.Request) error {
	return errors.New("failed to add auth")
}

func TestMultiAuthenticator(t *testing.T) {
	tests := []struct {
		name       string
		auths      []Authenticator
		expectAuth bool
		expectErr  bool
	}{
		{
			name:       "success auth first",
			auths:      []Authenticator{successAuth{}, failAuth{}},
			expectAuth: true,
			expectErr:  false,
		},
		{
			name:       "fail auth first",
			auths:      []Authenticator{failAuth{}, successAuth{}},
			expectAuth: true,
			expectErr:  false,
		},
		{
			name:       "all fail auth",
			auths:      []Authenticator{failAuth{}, failAuth{}},
			expectAuth: false,
			expectErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			multiAuth := MultiAuthenticator(tt.auths...)
			req, _ := http.NewRequest("GET", "http://example.com", nil)
			err := multiAuth.AddAuth(context.Background(), req)

			if tt.expectErr && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("did not expect error but got: %v", err)
			}

			user, pass, ok := req.BasicAuth()
			if tt.expectAuth && !ok {
				t.Errorf("expected auth but got none")
			}
			if !tt.expectAuth && ok {
				t.Errorf("did not expect auth but got user: %s, pass: %s", user, pass)
			}
		})
	}
}
