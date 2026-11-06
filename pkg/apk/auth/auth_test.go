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

func TestEnvAuth(t *testing.T) {
	tests := []struct {
		name       string
		env        string
		host       string // explicit req.Host, if different from the URL host
		emptyHost  bool   // clear req.Host, as a hand-built request may have it
		expectAuth bool
		expectUser string
		expectPass string
	}{
		{
			name:       "plain password",
			env:        "basic:example.com:user:pass",
			expectAuth: true,
			expectUser: "user",
			expectPass: "pass",
		},
		{
			name:       "password with one colon",
			env:        "basic:example.com:user:pa:ss",
			expectAuth: true,
			expectUser: "user",
			expectPass: "pa:ss",
		},
		{
			name:       "password with several colons",
			env:        "basic:example.com:user:p:a:s:s:",
			expectAuth: true,
			expectUser: "user",
			expectPass: "p:a:s:s:",
		},
		{
			name:       "too few parts",
			env:        "basic:example.com:user",
			expectAuth: false,
		},
		{
			name:       "wrong scheme",
			env:        "bearer:example.com:user:pass",
			expectAuth: false,
		},
		{
			name:       "host mismatch",
			env:        "basic:other.example.com:user:pass",
			expectAuth: false,
		},
		{
			name:       "unset",
			env:        "",
			expectAuth: false,
		},
		{
			name:       "explicit request Host matches",
			env:        "basic:other.example.com:user:pass",
			host:       "other.example.com",
			expectAuth: true,
			expectUser: "user",
			expectPass: "pass",
		},
		{
			name:       "explicit request Host differs",
			env:        "basic:example.com:user:pass",
			host:       "other.example.com",
			expectAuth: false,
		},
		{
			name:       "empty request Host",
			env:        "basic:example.com:user:pass",
			emptyHost:  true,
			expectAuth: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HTTP_AUTH", tt.env)
			req, _ := http.NewRequest("GET", "http://example.com", nil)
			if tt.host != "" {
				req.Host = tt.host
			}
			if tt.emptyHost {
				req.Host = ""
			}
			if err := (EnvAuth{}).AddAuth(context.Background(), req); err != nil {
				t.Fatalf("did not expect error but got: %v", err)
			}

			user, pass, ok := req.BasicAuth()
			if ok != tt.expectAuth {
				t.Fatalf("expected auth=%v, got auth=%v (user: %q, pass: %q)", tt.expectAuth, ok, user, pass)
			}
			if !ok {
				return
			}
			if user != tt.expectUser {
				t.Errorf("expected user %q, got %q", tt.expectUser, user)
			}
			if pass != tt.expectPass {
				t.Errorf("expected pass %q, got %q", tt.expectPass, pass)
			}
		})
	}
}
