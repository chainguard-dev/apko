// Copyright 2026 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package apk

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // this is what apk tools is using
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"chainguard.dev/apko/pkg/apk/auth"
	"chainguard.dev/apko/pkg/apk/expandapk"
	"chainguard.dev/apko/pkg/apk/expandapk/tarfs"
	"chainguard.dev/apko/pkg/paths"

	"github.com/chainguard-dev/clog"
)

// PackageGetter abstracts how packages are fetched and expanded.
type PackageGetter interface {
	// GetPackage fetches and returns an expanded package.
	GetPackage(ctx context.Context, pkg InstallablePackage) (*expandapk.APKExpanded, error)
}

// globalApkCache is the shared in-memory singleflight cache used by DefaultPackageGetter.
// This ensures deduplication of concurrent requests across all APK instances in a process.
// NOTE: This is used only to retain backwards compatibility with existing behavior, which
// also uses a global cache.
var globalApkCache = newFlightCache[string, *expandapk.APKExpanded]()

// defaultPackageGetter implements the standard disk-caching behavior
// with in-memory singleflight deduplication using a global cache.
type defaultPackageGetter struct {
	client            *http.Client
	cache             *cache
	auth              auth.Authenticator
	apkControlMaxSize int64
	apkDataMaxSize    int64
}

// packageGetterOption is a functional option for configuring defaultPackageGetter.
type packageGetterOption func(*defaultPackageGetter)

// withAPKControlMaxSize sets the maximum decompressed size for APK control sections.
func withAPKControlMaxSize(size int64) packageGetterOption {
	return func(d *defaultPackageGetter) {
		d.apkControlMaxSize = size
	}
}

// withAPKDataMaxSize sets the maximum decompressed size for APK data sections.
func withAPKDataMaxSize(size int64) packageGetterOption {
	return func(d *defaultPackageGetter) {
		d.apkDataMaxSize = size
	}
}

// newDefaultPackageGetter creates a new defaultPackageGetter with the given configuration.
func newDefaultPackageGetter(client *http.Client, cache *cache, authenticator auth.Authenticator, opts ...packageGetterOption) *defaultPackageGetter {
	d := &defaultPackageGetter{
		client: client,
		cache:  cache,
		auth:   authenticator,
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// GetPackage fetches and returns an expanded package.
// If a disk cache is configured, it uses a global singleflight cache to deduplicate
// concurrent requests across all APK instances in the process.
func (d *defaultPackageGetter) GetPackage(ctx context.Context, pkg InstallablePackage) (*expandapk.APKExpanded, error) {
	if d.cache == nil {
		// If we don't have a cache configured, don't use the global cache.
		// Calling APKExpanded.Close() will clean up a tempdir.
		// This is fine when we have a cache because we move all the backing files into the cache.
		// This is not fine when we don't have a cache because the tempdir contains all our state.
		return d.getPackageImpl(ctx, pkg)
	}

	cached := true
	val, err := globalApkCache.Do(pkg.URL(), func() (*expandapk.APKExpanded, error) {
		cached = false
		return d.getPackageImpl(ctx, pkg)
	})
	if !cached {
		// We've just executed the callback - either successfully cached or
		// failed (errors aren't cached). Either way, no validation needed.
		return val, err
	}
	if val != nil {
		// If we find a value in the cache, we should check to make sure the tar file it references still exists.
		// If it references a non-existent file, we should act as though this was a cache miss and expand the
		// APK again.
		if !val.IsValid() {
			globalApkCache.Forget(pkg.URL())
			return d.getPackageImpl(ctx, pkg)
		}
	}
	return val, err
}

// getPackageImpl is the actual implementation that fetches/expands/caches a package.
func (d *defaultPackageGetter) getPackageImpl(ctx context.Context, pkg InstallablePackage) (*expandapk.APKExpanded, error) {
	log := clog.FromContext(ctx)
	ctx, span := otel.Tracer("go-apk").Start(ctx, "getPackageImpl", trace.WithAttributes(attribute.String("package", pkg.PackageName())))
	defer span.End()

	cacheDir := ""
	if d.cache != nil {
		var err error
		cacheDir, err = cacheDirForPackage(d.cache.dir, pkg)
		if err != nil {
			return nil, err
		}

		exp, err := d.cachedPackage(ctx, pkg, cacheDir)
		if err == nil {
			log.Debugf("cache hit (%s)", pkg.PackageName())
			return exp, nil
		}

		log.Debugf("cache miss (%s): %v", pkg.PackageName(), err)

		if err := os.MkdirAll(cacheDir, 0o755); err != nil {
			return nil, fmt.Errorf("unable to create cache directory %q: %w", cacheDir, err)
		}
	}

	rc, err := d.fetchPackage(ctx, pkg)
	if err != nil {
		return nil, fmt.Errorf("fetching package %q: %w", pkg.PackageName(), err)
	}
	defer rc.Close()

	var expandOpts []expandapk.Option
	if d.apkControlMaxSize != 0 {
		expandOpts = append(expandOpts, expandapk.WithMaxControlSize(d.apkControlMaxSize))
	}
	if d.apkDataMaxSize != 0 {
		expandOpts = append(expandOpts, expandapk.WithMaxDataSize(d.apkDataMaxSize))
	}
	exp, err := expandapk.ExpandApkWithOptions(ctx, rc, cacheDir, expandOpts...)
	if err != nil {
		return nil, fmt.Errorf("expanding %s: %w", pkg.PackageName(), err)
	}

	// If we don't have a cache, we're done.
	if d.cache == nil {
		return exp, nil
	}

	return d.cachePackage(ctx, pkg, exp, cacheDir)
}

// fetchPackage fetches a package from the network or local filesystem.
func (d *defaultPackageGetter) fetchPackage(ctx context.Context, pkg FetchablePackage) (io.ReadCloser, error) {
	log := clog.FromContext(ctx)
	log.Debugf("fetching %s", pkg)

	ctx, span := otel.Tracer("go-apk").Start(ctx, "fetchPackage", trace.WithAttributes(attribute.String("package", pkg.PackageName())))
	defer span.End()

	u := pkg.URL()

	// Normalize the repo as a URI, so that local paths
	// are translated into file:// URLs, allowing them to be parsed
	// into a url.URL{}.
	asURL, err := packageAsURL(pkg)
	if err != nil {
		return nil, fmt.Errorf("failed to parse package as URL: %w", err)
	}

	switch asURL.Scheme {
	case "file":
		f, err := os.Open(u)
		if err != nil {
			return nil, fmt.Errorf("failed to read repository package apk %s: %w", u, err)
		}
		return f, nil
	case "https", "http":
		client := d.client
		if d.cache != nil {
			client = d.cache.client(client, false)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		if err := d.auth.AddAuth(ctx, req); err != nil {
			return nil, err
		}

		// This will return a body that retries requests using Range requests if Read() hits an error.
		rrt := NewRangeRetryTransport(client.Transport)
		res, err := rrt.RoundTrip(req)
		if err != nil {
			return nil, fmt.Errorf("unable to get package apk at %s: %w", u, err)
		}
		if res.StatusCode != http.StatusOK {
			res.Body.Close()
			return nil, fmt.Errorf("unable to get package apk at %s: %v", u, res.Status)
		}
		return res.Body, nil
	default:
		return nil, fmt.Errorf("repository scheme %s not supported", asURL.Scheme)
	}
}

// cachePackage moves expanded package files to the cache directory.
func (d *defaultPackageGetter) cachePackage(ctx context.Context, pkg InstallablePackage, exp *expandapk.APKExpanded, cacheDir string) (*expandapk.APKExpanded, error) {
	_, span := otel.Tracer("go-apk").Start(ctx, "cachePackage", trace.WithAttributes(attribute.String("package", pkg.PackageName())))
	defer span.End()

	// Rename exp's temp files to content-addressable identifiers in the cache.

	ctlHex := hex.EncodeToString(exp.ControlHash)
	ctlDst := filepath.Join(cacheDir, ctlHex+".ctl.tar.gz")

	if err := paths.AdvertiseCachedFile(exp.ControlFile, ctlDst); err != nil {
		return nil, err
	}

	exp.ControlFile = ctlDst

	if exp.SignatureFile != "" {
		sigDst := filepath.Join(cacheDir, ctlHex+".sig.tar.gz")

		if err := paths.AdvertiseCachedFile(exp.SignatureFile, sigDst); err != nil {
			return nil, err
		}

		exp.SignatureFile = sigDst
	}

	datHex := hex.EncodeToString(exp.PackageHash)
	datDst := filepath.Join(cacheDir, datHex+".dat.tar.gz")

	if err := paths.AdvertiseCachedFile(exp.PackageFile, datDst); err != nil {
		return nil, err
	}

	exp.PackageFile = datDst

	if err := exp.TarFS.Close(); err != nil {
		return nil, fmt.Errorf("closing tarfs: %w", err)
	}

	tarDst := strings.TrimSuffix(exp.PackageFile, ".gz")

	if err := paths.AdvertiseCachedFile(exp.TarFile, tarDst); err != nil {
		return nil, err
	}

	exp.TarFile = tarDst

	// Re-initialize the tarfs with the renamed file.
	// TODO: Split out the tarfs Index creation from the FS.
	// TODO: Consolidate ExpandAPK(), cachedPackage(), and cachePackage().
	data, err := exp.PackageData()
	if err != nil {
		return nil, err
	}
	info, err := data.Stat()
	if err != nil {
		return nil, err
	}
	exp.TarFS, err = tarfs.New(data, info.Size())
	if err != nil {
		return nil, err
	}

	return exp, nil
}

// cachedPackage attempts to load a package from the disk cache.
func (d *defaultPackageGetter) cachedPackage(ctx context.Context, pkg InstallablePackage, cacheDir string) (*expandapk.APKExpanded, error) {
	_, span := otel.Tracer("go-apk").Start(ctx, "cachedPackage", trace.WithAttributes(attribute.String("package", pkg.PackageName())))
	defer span.End()

	chk := pkg.ChecksumString()
	if !strings.HasPrefix(chk, "Q1") {
		return nil, fmt.Errorf("unexpected checksum: %q", chk)
	}

	checksum, err := base64.StdEncoding.DecodeString(chk[2:])
	if err != nil {
		return nil, err
	}

	pkgHexSum := hex.EncodeToString(checksum)

	exp := expandapk.APKExpanded{}

	ctl := filepath.Join(cacheDir, pkgHexSum+".ctl.tar.gz")
	cf, err := os.Stat(ctl)
	if err != nil {
		return nil, err
	}
	exp.ControlFile = ctl
	exp.ControlHash = checksum
	exp.ControlSize = cf.Size()

	control, err := exp.ControlData()
	if err != nil {
		return nil, err
	}

	exp.ControlFS, err = tarfs.New(bytes.NewReader(control), int64(len(control)))
	if err != nil {
		return nil, fmt.Errorf("indexing %q: %w", exp.ControlFile, err)
	}

	exp.Size += cf.Size()

	sig := filepath.Join(cacheDir, pkgHexSum+".sig.tar.gz")
	sf, err := os.Stat(sig)
	if err == nil {
		exp.SignatureFile = sig
		exp.Signed = true
		exp.Size += sf.Size()
		exp.SignatureSize = sf.Size()
		signatureData, err := os.ReadFile(sig)
		if err != nil {
			return nil, err
		}
		signatureHash := sha1.Sum(signatureData) //nolint:gosec // this is what apk tools is using
		exp.SignatureHash = signatureHash[:]
	}

	pkgInfo, err := exp.PkgInfo()
	if err != nil {
		return nil, fmt.Errorf("reading pkginfo from %s: %w", pkg, err)
	}

	dat := filepath.Join(cacheDir, pkgInfo.DataHash+".dat.tar.gz")
	df, err := os.Stat(dat)
	if err != nil {
		return nil, err
	}
	exp.PackageFile = dat
	exp.PackageSize = df.Size()
	exp.Size += df.Size()

	exp.PackageHash, err = hex.DecodeString(pkgInfo.DataHash)
	if err != nil {
		return nil, err
	}

	exp.TarFile = strings.TrimSuffix(exp.PackageFile, ".gz")
	data, err := exp.PackageData()
	if err != nil {
		return nil, err
	}
	info, err := data.Stat()
	if err != nil {
		return nil, err
	}
	exp.TarFS, err = tarfs.New(data, info.Size())
	if err != nil {
		return nil, err
	}

	return &exp, nil
}
