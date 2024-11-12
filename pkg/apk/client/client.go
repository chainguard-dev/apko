package client

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sync"

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

	// map of package name to latest package with that name.
	latestMap map[string]*apk.Package
	once      sync.Once
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
//
// `apkRepo` is the URL of the repository including the protocol, e.g.
// "https://packages.wolfi.dev/os".
//
// `arch` is the architecture of the index, e.g. "x86_64" or "aarch64".
func (c *Client) GetRemoteIndex(ctx context.Context, apkRepo, arch string) (*apk.APKIndex, error) {
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

func (c *Client) LatestPackage(idx *apk.APKIndex, name string) *apk.Package {
	c.once.Do(func() { c.latestMap = onlyLatest(idx.Packages) })
	return c.latestMap[name]
}

func onlyLatest(packages []*apk.Package) map[string]*apk.Package {
	highest := map[string]*apk.Package{}
	for _, pkg := range packages {
		got, err := apk.ParseVersion(pkg.Version)
		if err != nil {
			// TODO: We should really fail here.
			log.Printf("parsing %q: %v", pkg.Filename(), err)
			continue
		}

		have, ok := highest[pkg.Name]
		if !ok {
			highest[pkg.Name] = pkg
			continue
		}

		// TODO: We re-parse this for no reason.
		parsed, err := apk.ParseVersion(have.Version)
		if err != nil {
			// TODO: We should really fail here.
			log.Printf("parsing %q: %v", have.Version, err)
			continue
		}

		if apk.CompareVersions(got, parsed) > 0 {
			highest[pkg.Name] = pkg
		}
	}
	return highest
}
