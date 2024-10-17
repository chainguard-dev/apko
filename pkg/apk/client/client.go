package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path"

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/apko/pkg/apk/auth"
)

const (
	WolfiAPKRepo                = "https://packages.wolfi.dev/os"
	ChainguardEnterpriseAPKRepo = "https://apk.cgr.dev/chainguard-private"
	ChainguardExtrasAPKRepo     = "https://apk.cgr.dev/extra-packages"
)

const (
	Aarch64Arch = "aarch64"
	X86_64Arch  = "x86_64"
)

// Client is a client for interacting with an APK package repository.
type Client struct {
	httpClient *http.Client
}

// New creates a new Client, suitable for accessing remote APK indexes and
// packages.
func New(httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{httpClient: httpClient}
}

// GetRemoteIndex retrieves the index of APK packages from the specified remote
// repository.
func (c Client) GetRemoteIndex(ctx context.Context, apkRepo, arch string) (*apk.APKIndex, error) {
	indexURL := apk.IndexURL(apkRepo, arch)

	u, err := url.Parse(indexURL)
	if err != nil {
		return nil, fmt.Errorf("parsing %q: %w", indexURL, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("GET %q: %w", u.Redacted(), err)
	}
	if err := auth.DefaultAuthenticators.AddAuth(ctx, req); err != nil {
		return nil, fmt.Errorf("error adding auth: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %q: %w", u.Redacted(), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("GET %q: status %d: %s", u.Redacted(), resp.StatusCode, resp.Status)
	}

	return apk.IndexFromArchive(resp.Body)
}

// pkgver the package and version as a string, like "foo-bar-1.2.3-r0" (without .apk) meaning "package foo-bar version 1.2.3-r0"
func (c Client) GetRemotePackage(ctx context.Context, apkRepo, arch, pkgver string) (*apk.Package, error) {
	indexURL := apk.IndexURL(apkRepo, arch)
	u, err := url.Parse(indexURL)
	if err != nil {
		return nil, fmt.Errorf("parsing %q: %w", indexURL, err)
	}

	pkgurl := path.Join(u.String(), pkgver+".apk")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pkgurl, nil)
	if err != nil {
		return nil, fmt.Errorf("GET %q: %w", u.Redacted(), err)
	}
	if err := auth.DefaultAuthenticators.AddAuth(ctx, req); err != nil {
		return nil, fmt.Errorf("error adding auth: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %q: %w", u.Redacted(), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("GET %q: status %d: %s", u.Redacted(), resp.StatusCode, resp.Status)
	}

	return apk.ParsePackage(ctx, resp.Body, uint64(resp.ContentLength))
}
