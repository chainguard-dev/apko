package auth

import (
	"context"
	"errors"
	"net/http"
	"sync"
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HTTP_AUTH", tt.env)
			req, _ := http.NewRequest("GET", "http://example.com", nil)
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

func TestIsChainguardHost(t *testing.T) {
	for host, want := range map[string]bool{
		"apk.cgr.dev":              true,
		"apk.cgr.dev:443":          true,
		"APK.CGR.DEV":              true,
		"cgr.dev":                  true,
		"example.com":              false,
		"cgr.dev.evil.com":         false,
		"notcgr.dev":               false,
		"apk.cgr.dev.attacker.net": false,
	} {
		if got := isChainguardHost(host); got != want {
			t.Errorf("isChainguardHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestCGRAuthOnlyMatchesConfiguredHost(t *testing.T) {
	t.Setenv("APKO_APK_HOST", "apk.example.com")

	for _, target := range []string{"https://apk.cgr.dev/x", "https://other.example.com/x"} {
		req, err := http.NewRequest(http.MethodGet, target, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := (CGRAuth{}).AddAuth(context.Background(), req); err != nil {
			t.Fatalf("AddAuth(%s): %v", target, err)
		}
		if _, _, ok := req.BasicAuth(); ok {
			t.Errorf("AddAuth(%s) added credentials for a host other than APKO_APK_HOST", target)
		}
	}
}

// TestCGRAuthReadsCachedTokenConcurrently checks that AddAuth reads the
// cached token safely while it is being refreshed. The token is seeded
// directly and the once-per-interval chainctl call is consumed first, so no
// chainctl process runs here.
func TestCGRAuthReadsCachedTokenConcurrently(t *testing.T) {
	t.Setenv("APKO_APK_HOST", "apk.cgr.dev")
	sometimes.Do(func() {})
	seed := "test-token"
	tok.Store(&seed)
	t.Cleanup(func() { tok.Store(nil) })

	var wg sync.WaitGroup
	wg.Go(func() {
		for range 200 {
			refreshed := "test-token"
			tok.Store(&refreshed)
		}
	})
	for range 8 {
		wg.Go(func() {
			for range 50 {
				req, err := http.NewRequest(http.MethodGet, "https://apk.cgr.dev/x", nil)
				if err != nil {
					t.Error(err)
					return
				}
				if err := (CGRAuth{}).AddAuth(context.Background(), req); err != nil {
					t.Error(err)
					return
				}
				if _, pass, ok := req.BasicAuth(); !ok || pass != "test-token" {
					t.Errorf("AddAuth: basic auth = %q, %v; want the cached token", pass, ok)
					return
				}
			}
		})
	}
	wg.Wait()
}
