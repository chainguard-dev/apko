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
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"chainguard.dev/apko/pkg/apk/auth"
	"chainguard.dev/apko/pkg/apk/expandapk"
	"chainguard.dev/apko/pkg/apk/expandapk/tarfs"
	"chainguard.dev/apko/pkg/paths"

	"github.com/chainguard-dev/clog"
)

const (
	// maxFetchRetries is the number of additional attempts after the first failure.
	maxFetchRetries = 2
	// retryBaseDelay is the base delay between retry attempts (scaled linearly by attempt number).
	retryBaseDelay = 1 * time.Second
)

// isRetryableError reports whether err is a transient error that warrants retrying
// the fetch+expand pipeline from scratch.
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNABORTED) {
		return true
	}
	if _, ok := errors.AsType[*net.OpError](err); ok {
		return true
	}
	if httpErr, ok := errors.AsType[*httpStatusError](err); ok {
		return httpErr.statusCode >= 500 || httpErr.statusCode == http.StatusTooManyRequests
	}
	msg := err.Error()
	for _, substr := range []string{
		"unexpected EOF",
		"connection reset",
		"broken pipe",
	} {
		if strings.Contains(msg, substr) {
			return true
		}
	}
	return false
}

// httpStatusError represents a non-OK HTTP response status.
type httpStatusError struct {
	statusCode int
	status     string
	url        string
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("unable to get package apk at %s: %s", e.url, e.status)
}

// PackageGetter abstracts how packages are fetched and expanded.
type PackageGetter interface {
	// GetPackage fetches and returns an expanded package.
	GetPackage(ctx context.Context, pkg InstallablePackage) (*expandapk.APKExpanded, error)
}

const packageCacheMaxEntries = 4096

// globalApkCache is the shared in-memory singleflight cache used by DefaultPackageGetter.
// This ensures deduplication of concurrent requests across all APK instances in a process.
var globalApkCache = newFlightCache[string, *expandapk.APKExpanded](packageCacheMaxEntries)

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

// expandOptions returns the configured section size limits. Both the fetch and
// the cache-read path need these; the latter is easy to miss because it builds
// its APKExpanded by hand instead of going through ExpandApkWithOptions.
func (d *defaultPackageGetter) expandOptions() []expandapk.Option {
	var opts []expandapk.Option
	if d.apkControlMaxSize != 0 {
		opts = append(opts, expandapk.WithMaxControlSize(d.apkControlMaxSize))
	}
	if d.apkDataMaxSize != 0 {
		opts = append(opts, expandapk.WithMaxDataSize(d.apkDataMaxSize))
	}
	return opts
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

	val, cached, err := globalApkCache.Do(pkg.URL(), func() (*expandapk.APKExpanded, error) {
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

	exp, err := d.fetchExpandAndVerify(ctx, pkg, cacheDir, d.expandOptions())
	if err != nil {
		return nil, err
	}

	// If we don't have a cache, we're done.
	if d.cache == nil {
		return exp, nil
	}

	return d.cachePackage(ctx, pkg, exp, cacheDir)
}

// fetchExpandAndVerify fetches, expands, and verifies a package, retrying on transient errors.
func (d *defaultPackageGetter) fetchExpandAndVerify(ctx context.Context, pkg InstallablePackage, cacheDir string, expandOpts []expandapk.Option) (*expandapk.APKExpanded, error) {
	var lastErr error
	for attempt := range maxFetchRetries + 1 {
		if attempt > 0 {
			delay := time.Duration(attempt) * retryBaseDelay
			clog.FromContext(ctx).Warnf("retrying fetch of %s (attempt %d/%d) after error: %v", pkg.PackageName(), attempt+1, maxFetchRetries+1, lastErr)
			select {
			case <-ctx.Done():
				return nil, context.Cause(ctx)
			case <-time.After(delay):
			}
		}

		exp, err := d.doFetchExpandAndVerify(ctx, pkg, cacheDir, expandOpts)
		if err == nil {
			return exp, nil
		}
		if !isRetryableError(err) {
			return nil, err
		}
		lastErr = err
	}
	return nil, fmt.Errorf("after %d attempts: %w", maxFetchRetries+1, lastErr)
}

// doFetchExpandAndVerify performs a single fetch+expand+verify cycle for a package.
func (d *defaultPackageGetter) doFetchExpandAndVerify(ctx context.Context, pkg InstallablePackage, cacheDir string, expandOpts []expandapk.Option) (*expandapk.APKExpanded, error) {
	rc, err := d.fetchPackage(ctx, pkg)
	if err != nil {
		return nil, fmt.Errorf("fetching package %q: %w", pkg.PackageName(), err)
	}
	defer rc.Close()

	exp, err := expandapk.ExpandApkWithOptions(ctx, rc, cacheDir, expandOpts...)
	if err != nil {
		return nil, fmt.Errorf("expanding %s: %w", pkg.PackageName(), err)
	}

	chk := pkg.ChecksumString()
	if !strings.HasPrefix(chk, "Q1") {
		_ = exp.Close()
		return nil, fmt.Errorf("package %q has unexpected checksum format: %q", pkg.PackageName(), chk)
	}
	expectedControlHash, err := base64.StdEncoding.DecodeString(chk[2:])
	if err != nil {
		_ = exp.Close()
		return nil, fmt.Errorf("package %q has malformed checksum %q: %w", pkg.PackageName(), chk, err)
	}
	if !bytes.Equal(expectedControlHash, exp.ControlHash) {
		_ = exp.Close()
		return nil, fmt.Errorf("package %q control hash mismatch: expected %x, got %x", pkg.PackageName(), expectedControlHash, exp.ControlHash)
	}

	pkgInfo, err := exp.PkgInfo()
	if err != nil {
		_ = exp.Close()
		return nil, fmt.Errorf("reading pkginfo for %s: %w", pkg.PackageName(), err)
	}
	expectedDataHash, err := hex.DecodeString(pkgInfo.DataHash)
	if err != nil {
		_ = exp.Close()
		return nil, fmt.Errorf("package %q has malformed datahash %q: %w", pkg.PackageName(), pkgInfo.DataHash, err)
	}
	if !bytes.Equal(expectedDataHash, exp.PackageHash) {
		_ = exp.Close()
		return nil, fmt.Errorf("package %q data hash mismatch: expected %x, got %x", pkg.PackageName(), expectedDataHash, exp.PackageHash)
	}

	return exp, nil
}

// sha1File returns the SHA-1 of the file at path.
func sha1File(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha1.New() //nolint:gosec // this is what apk tools is using
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
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
			return nil, &httpStatusError{statusCode: res.StatusCode, status: res.Status, url: u}
		}
		return res.Body, nil
	default:
		return nil, fmt.Errorf("repository scheme %s not supported", asURL.Scheme)
	}
}

// replaceCachedFile is what cachePackage publishes through, as a seam for
// tests: the races cachePackage has to survive are another process republishing
// an entry in the instant after this one published it, which no test can force
// from outside, so tests disturb the entry from here instead.
var replaceCachedFile = paths.ReplaceCachedFile

// cachePackage moves expanded package files to the cache directory.
func (d *defaultPackageGetter) cachePackage(ctx context.Context, pkg InstallablePackage, exp *expandapk.APKExpanded, cacheDir string) (*expandapk.APKExpanded, error) {
	_, span := otel.Tracer("go-apk").Start(ctx, "cachePackage", trace.WithAttributes(attribute.String("package", pkg.PackageName())))
	defer span.End()

	// Measure the data section before publishing anything, from this process's
	// own copy, and serve only what that produces.
	//
	// It has to happen first, and from exp's own file rather than the published
	// name, because once an entry is published this process no longer controls
	// what the name resolves to. A concurrent cachePackage for the same package
	// republishes it and unlinks the copy it displaced, so a read through the name
	// can land on that unlinked copy and fail with ENOENT; on ext4 and btrfs,
	// open() through a symlink being renamed over can even return the link's
	// parent directory; and any writer to the cache can put other bytes there,
	// turning a download that verified into a hash mismatch.
	// Before publication, exp.PackageFile is only reachable inside the 0700
	// directory ExpandApk created, and nothing else publishes or unlinks it.
	//
	// Measured rather than merely reopened, all the same: VerifiedPackageData
	// re-hashes against the datahash from the verified control section and
	// inflates into an unlinked private copy, which is the only thing served.
	//
	// Nothing is published yet, so a failure here has to dispose of exp itself:
	// its TarFS still holds a descriptor, and its temp directory is in the shared
	// cache directory where nothing will ever reference or remove it.
	// TODO: Split out the tarfs Index creation from the FS.
	// TODO: Consolidate ExpandAPK(), cachedPackage(), and cachePackage().
	discard := func() {
		_ = exp.TarFS.Close()
		_ = exp.Close()
	}
	data, err := exp.VerifiedPackageData(exp.PackageHash)
	if err != nil {
		discard()
		return nil, fmt.Errorf("caching %q: %w", exp.PackageFile, err)
	}
	info, err := data.Stat()
	if err != nil {
		data.Close()
		discard()
		return nil, err
	}
	verified, err := tarfs.New(data, info.Size())
	if err != nil {
		data.Close()
		discard()
		return nil, err
	}

	if err := exp.TarFS.Close(); err != nil {
		data.Close()
		_ = exp.Close()
		return nil, fmt.Errorf("closing tarfs: %w", err)
	}
	exp.TarFS = verified

	// The private copy is exp's only data from here on, so any failure to
	// publish has to release it.
	exp, err = publishPackage(exp, cacheDir)
	if err != nil {
		data.Close()
		return nil, err
	}
	return exp, nil
}

// publishPackage renames exp's temp files to their content-addressable names in
// cacheDir. It publishes; it does not read anything back, since what a name
// resolves to once published is not this process's to decide.
func publishPackage(exp *expandapk.APKExpanded, cacheDir string) (*expandapk.APKExpanded, error) {
	// These use ReplaceCachedFile rather than AdvertiseCachedFile: everything here
	// has just been fetched and verified by doFetchExpandAndVerify, so it must win
	// over whatever is already sitting at the destination. Deferring to an existing
	// entry would let a poisoned cache survive its own rejection -- cachedPackage
	// refuses it, the refetch lands here, and adopting the planted file would serve
	// exactly the content the refetch was supposed to replace.

	ctlHex := hex.EncodeToString(exp.ControlHash)
	ctlDst := filepath.Join(cacheDir, ctlHex+".ctl.tar.gz")

	if err := replaceCachedFile(exp.ControlFile, ctlDst); err != nil {
		return nil, err
	}

	exp.ControlFile = ctlDst

	if exp.SignatureFile != "" {
		sigDst := filepath.Join(cacheDir, ctlHex+".sig.tar.gz")

		if err := replaceCachedFile(exp.SignatureFile, sigDst); err != nil {
			return nil, err
		}

		exp.SignatureFile = sigDst
	}

	datHex := hex.EncodeToString(exp.PackageHash)
	datDst := filepath.Join(cacheDir, datHex+".dat.tar.gz")

	if err := replaceCachedFile(exp.PackageFile, datDst); err != nil {
		return nil, err
	}

	exp.PackageFile = datDst

	tarDst := strings.TrimSuffix(exp.PackageFile, ".gz")

	if err := replaceCachedFile(exp.TarFile, tarDst); err != nil {
		return nil, err
	}

	exp.TarFile = tarDst

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
	if err := exp.ApplyOptions(d.expandOptions()...); err != nil {
		return nil, err
	}

	ctl := filepath.Join(cacheDir, pkgHexSum+".ctl.tar.gz")
	cf, err := os.Stat(ctl)
	if err != nil {
		return nil, err
	}

	// Recompute rather than trust the content-addressable filename; a tampered cache entry must not bypass fetch-path verification.
	ctlHash, err := sha1File(ctl)
	if err != nil {
		return nil, fmt.Errorf("hashing cached control %q: %w", ctl, err)
	}
	if !bytes.Equal(checksum, ctlHash) {
		return nil, fmt.Errorf("cached %q: control hash mismatch: expected %x, got %x", ctl, checksum, ctlHash)
	}

	exp.ControlFile = ctl
	exp.ControlHash = ctlHash
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

	// As with the control section above, recompute rather than trust the
	// content-addressable filename. datahash is usable as the anchor here
	// precisely because it came from the control section the Q1 checksum just
	// vouched for.
	data, err := exp.VerifiedPackageData(exp.PackageHash)
	if err != nil {
		return nil, fmt.Errorf("cached %q: %w", exp.PackageFile, err)
	}
	info, err := data.Stat()
	if err != nil {
		data.Close()
		return nil, err
	}
	exp.TarFS, err = tarfs.New(data, info.Size())
	if err != nil {
		data.Close()
		return nil, err
	}

	return &exp, nil
}
