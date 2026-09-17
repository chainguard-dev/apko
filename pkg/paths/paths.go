// Copyright 2025 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package paths

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
)

func ResolvePath(p string, includePaths []string) (string, error) {
	_, err := os.Stat(p)
	if err == nil {
		return p, nil
	}
	for _, pathPrefix := range includePaths {
		resolvedPath := path.Join(pathPrefix, p)
		_, err := os.Stat(resolvedPath)
		if err == nil {
			return resolvedPath, nil
		}
	}
	return "", os.ErrNotExist
}

// AdvertisedCachedFile will create a symlink at `dst` pointing to `src`.
//
// In the case that `dst` already exists, another process had already created the symlink
// and we can safely move on. We will also perform a best-effort attempt to clean up the
// unadvertised file at `src`.
func AdvertiseCachedFile(src, dst string) error {
	// Prefer relative symlinks
	rel, err := filepath.Rel(filepath.Dir(dst), src)
	if err != nil {
		rel = src
	}

	// Check what exists at dst using Lstat (doesn't follow symlinks).
	// This lets us distinguish between "nothing exists" and "broken symlink".
	if _, err := os.Lstat(dst); err == nil {
		// Something exists at dst. Check if it's a valid symlink by following it.
		if _, err := os.Stat(dst); err == nil {
			// Valid symlink exists - another process already advertised.
			// Clean up src since it's unadvertised and return.
			_ = os.Remove(src)
			return nil
		}
		// Broken symlink (Lstat succeeded but Stat failed) - remove it.
		if err := os.Remove(dst); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				// Race condition: something removed it between our Lstat and Remove.
				// Re-run to handle it properly.
				return AdvertiseCachedFile(src, dst)
			}
			return fmt.Errorf("removing broken symlink %s: %w", dst, err)
		}
	}

	// Create the symlink.
	if err := os.Symlink(rel, dst); err != nil {
		if errors.Is(err, os.ErrExist) {
			// Race condition: something appeared between our Lstat check and Symlink.
			// Re-run to handle it properly.
			return AdvertiseCachedFile(src, dst)
		}
		return fmt.Errorf("linking (cached) %s to %s: %w", rel, dst, err)
	}
	return nil
}

// ReplaceCachedFile points `dst` at `src`, replacing whatever was there.
//
// It differs from AdvertiseCachedFile in who wins a collision. AdvertiseCachedFile
// defers to an existing entry, on the assumption that another process advertised
// equivalent content first. That assumption does not hold for a cache directory an
// attacker can write to: a planted entry would be adopted and the caller's own file
// discarded. Callers that hold content they have just verified use this instead, so
// the verified copy wins.
//
// The replacement goes through a uniquely named temporary symlink and a rename, so
// `dst` is never observed missing or half-written by a concurrent reader.
//
// Winning the collision means the entry that lost has to be disposed of, or the
// cache grows without bound. AdvertiseCachedFile removed the loser's `src`
// because it was the loser; here the loser is whatever `dst` already pointed at,
// and the rename replaces only the symlink, not its target. See orphanedTarget
// for why that removal is deliberately narrow.
//
// That disposal makes one demand of callers: advertise a given `src` at most
// once. Once a file has lost a collision it has been deleted, so re-advertising
// it points `dst` at something that no longer exists. Each caller advertising
// files it just created — which is what holding freshly verified content means —
// satisfies this without having to think about it.
func ReplaceCachedFile(src, dst string) error {
	// Prefer relative symlinks
	rel, err := filepath.Rel(filepath.Dir(dst), src)
	if err != nil {
		rel = src
	}

	// Read before replacing; afterwards the link is gone and the target is
	// unreachable rather than merely unreferenced.
	orphan := orphanedTarget(src, dst)

	// Reserve a unique name next to dst. os.CreateTemp is O_EXCL, so no concurrent
	// caller holds this name; removing the placeholder frees it for the symlink.
	tmp, err := os.CreateTemp(filepath.Dir(dst), filepath.Base(dst)+".link-*")
	if err != nil {
		return fmt.Errorf("creating temp link for %s: %w", dst, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename below succeeds

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing %s: %w", tmpName, err)
	}
	if err := os.Remove(tmpName); err != nil {
		return fmt.Errorf("clearing %s: %w", tmpName, err)
	}
	if err := os.Symlink(rel, tmpName); err != nil {
		return fmt.Errorf("linking (cached) %s to %s: %w", rel, tmpName, err)
	}

	if err := os.Rename(tmpName, dst); err == nil {
		removeOrphan(dst, orphan)
		return nil
	} else if !isNotReplaceable(err) {
		return fmt.Errorf("renaming %s onto %s: %w", tmpName, dst, err)
	}

	// rename(2) will not replace a directory with a symlink, so a directory
	// planted at a content-addressable name would wedge this entry permanently:
	// the read path rejects it, the refetch lands here, and every later run
	// repeats that forever. Nothing legitimate creates a directory at one of
	// these names, so clear it and retry.
	if err := os.RemoveAll(dst); err != nil {
		return fmt.Errorf("removing %s to make way for %s: %w", dst, rel, err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return fmt.Errorf("renaming %s onto %s: %w", tmpName, dst, err)
	}
	removeOrphan(dst, orphan)
	return nil
}

// orphanedTarget returns the file that replacing dst with src would strand, or
// "" when there is nothing to clean up.
//
// A rename over a *regular* file drops its last link, so only a symlink leaves
// anything behind: the link is replaced and whatever it addressed stays on disk,
// unreferenced and unreachable. In a shared cache that is every lost fetch race
// and every poison repair, none of which any later run will revisit.
//
// The result is deliberately confined to dst's own directory. dst lives in a
// cache an attacker may be able to write, so removing whatever the old link
// addressed, wherever it addressed, would be an arbitrary-file-deletion
// primitive: plant dst as a symlink to any path on the host and the next
// legitimate replacement unlinks it. Confining removal to the directory the
// caller is already writing keeps a planted link from reaching outside it, where
// deletion grants nothing beyond the write access the attacker must already have.
func orphanedTarget(src, dst string) string {
	target := resolveLink(dst)
	if target == "" {
		return ""
	}

	// Never the file being advertised: re-advertising an entry that already points
	// at src must not delete src.
	if abs, err := filepath.Abs(src); err == nil && filepath.Clean(abs) == target {
		return ""
	}
	if target == filepath.Clean(dst) {
		return ""
	}

	dir := filepath.Dir(dst)
	rel, err := filepath.Rel(dir, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return ""
	}
	return target
}

// resolveLink returns the absolute path a symlink addresses, or "" if the path is
// not a symlink.
func resolveLink(path string) string {
	target, err := os.Readlink(path)
	if err != nil {
		return ""
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(path), target)
	}
	return filepath.Clean(target)
}

// removeOrphan discards a stranded cache file, and the expand-apk directory that
// held it once it empties.
//
// Best effort throughout: another process may be doing the same cleanup, and
// losing that race costs disk rather than correctness. The re-check exists for
// the interleaving that does matter -- a concurrent replacement re-advertising
// this exact file between our rename and this call, which would leave dst
// dangling. Narrowing that window is worth five lines; closing it entirely is
// not, because the read path treats a dangling entry as a miss and the refetch
// repairs it.
func removeOrphan(dst, target string) {
	if target == "" || resolveLink(dst) == target {
		return
	}
	if err := os.Remove(target); err != nil {
		return
	}
	// Empty-only by construction: os.Remove refuses a non-empty directory, so a
	// temp dir still backing other cache entries survives.
	_ = os.Remove(filepath.Dir(target))
}

// isNotReplaceable reports whether err is rename(2) refusing to replace the
// destination because of what is already there, rather than a real I/O failure.
// Linux reports EISDIR or ENOTDIR depending on which side is the directory, and
// ENOTEMPTY or EEXIST for a non-empty one.
func isNotReplaceable(err error) bool {
	return errors.Is(err, syscall.EISDIR) ||
		errors.Is(err, syscall.ENOTDIR) ||
		errors.Is(err, syscall.ENOTEMPTY) ||
		errors.Is(err, syscall.EEXIST)
}
