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
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// OfflineChecksumExt is appended to a cached apk's name to form the sidecar file
// recording the checksum that the repository index reported for it. The apk's
// own bytes cannot serve as their own reference: the checksum is a hash of a
// section of the apk, so recomputing it from the file proves only that the file
// is internally consistent. The sidecar is meaningful because it was written
// while the index was trusted.
const OfflineChecksumExt = ".Q1"

// APKURL returns the URL an apk is fetched from, given the repository it lives
// in and a fully pinned name and version. It matches RepositoryPackage.URL() so
// that a package located this way lands on the same offline cache path that
// populating the cache from a normal resolve would have written.
func APKURL(repo, arch, name, version string) string {
	return fmt.Sprintf("%s/%s/%s-%s.apk", repo, arch, name, version)
}

// IsRemoteURL reports whether u names a package that would be fetched over the
// network, and so is a candidate for the offline cache. Local repositories need
// no caching.
func IsRemoteURL(u string) bool {
	return strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "http://")
}

// OfflineCachePath maps a remote package URL to its location beneath an offline
// cache directory. The layout is <dir>/<host>/<path>, mirroring the repository's
// own URL structure, so the directory can be populated from or diffed against an
// ordinary apk mirror.
func OfflineCachePath(dir, pkgURL string) (string, error) {
	u, err := url.Parse(pkgURL)
	if err != nil {
		return "", fmt.Errorf("parsing package url %q: %w", pkgURL, err)
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return "", fmt.Errorf("offline cache holds only remote packages, got scheme %q in %q", u.Scheme, pkgURL)
	}
	if u.Host == "" {
		return "", fmt.Errorf("package url %q has no host", pkgURL)
	}
	if filepath.Ext(u.Path) != ".apk" {
		return "", fmt.Errorf("package url %q does not name an .apk", pkgURL)
	}
	return offlineCacheJoin(dir, u.Host, u.Path)
}

// offlineCacheJoin joins elems beneath dir, refusing any result that escapes it.
// The host and path components come from a user-supplied config and may contain
// traversal sequences, either literally or via percent-encoding that url.Parse
// decodes for us.
func offlineCacheJoin(dir string, elems ...string) (string, error) {
	if dir == "" {
		return "", errors.New("offline cache directory is empty")
	}
	root := filepath.Clean(dir)
	p := filepath.Join(append([]string{root}, elems...)...)
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return "", fmt.Errorf("offline cache path %q is not within %q: %w", p, root, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("offline cache path %q escapes %q", p, root)
	}
	return p, nil
}

// OfflineChecksumPath returns the path of the sidecar recording apkPath's
// expected checksum.
func OfflineChecksumPath(apkPath string) string {
	return apkPath + OfflineChecksumExt
}

// ReadOfflineChecksum returns the checksum recorded alongside a cached apk, in
// the "Q1<base64>" form that ChecksumString produces.
func ReadOfflineChecksum(apkPath string) (string, error) {
	p := OfflineChecksumPath(apkPath)
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	chk := strings.TrimSpace(string(b))
	if !strings.HasPrefix(chk, "Q1") {
		return "", fmt.Errorf("%s: expected a Q1-prefixed checksum, got %q", p, chk)
	}
	return chk, nil
}

// writeOfflineChecksum records checksum for the apk at apkPath. It writes to a
// unique temporary name and renames, so that concurrent builds sharing one cache
// never observe a half-written sidecar.
func writeOfflineChecksum(apkPath, checksum string) error {
	p := OfflineChecksumPath(apkPath)
	tmp, err := os.CreateTemp(filepath.Dir(p), filepath.Base(p)+".tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.WriteString(checksum + "\n"); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), p)
}
