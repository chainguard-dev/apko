package lock

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"

	"chainguard.dev/apko/pkg/build/types"
)

type Lock struct {
	Version  string       `json:"version"`
	Config   *Config      `json:"config,omitempty"`
	Contents LockContents `json:"contents"`
}

// Origin describes the source file used to generate the lock file.
// Used to detect that the origin got changed without regenerating the lockfile.
type Config struct {
	Name string `json:"name,omitempty"`
	// This checksum also covers included files and command-line settings that influence the artifacts resolution.
	DeepChecksum string `json:"checksum,omitempty"`
}

type LockContents struct {
	Keyrings                []LockKeyring `json:"keyring"`
	BuildRepositories       []LockRepo    `json:"build_repositories"`
	RuntimeOnlyRepositories []LockRepo    `json:"runtime_repositories"`
	Repositories            []LockRepo    `json:"repositories"`
	// Packages in order of installation -> for a single architecture.
	Packages []LockPkg `json:"packages"`
}

type LockPkg struct {
	Name         string                  `json:"name"`
	URL          string                  `json:"url"`
	Version      string                  `json:"version"`
	Architecture string                  `json:"architecture"`
	Signature    LockPkgRangeAndChecksum `json:"signature"`
	Control      LockPkgRangeAndChecksum `json:"control"`
	Data         LockPkgRangeAndChecksum `json:"data"`
	// Checksum is APK-style: 'Q1' prefixed SHA1 hash of the second gzip stream (control stream) in the package.
	// For data-consistency checks use Signature, Control & Data above.
	// Populated since Apko 0.13.
	Checksum string `json:"checksum"`
}
type LockPkgRangeAndChecksum struct {
	Range    string `json:"range"`
	Checksum string `json:"checksum"`
}

type LockRepo struct {
	Name         string `json:"name"`
	URL          string `json:"url"`
	Architecture string `json:"architecture"`
}

type LockKeyring struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	// Content is the raw keyring content (typically a PEM-encoded public key).
	Content string `json:"content,omitempty"`
}

func FromFile(lockFile string) (Lock, error) {
	payload, err := os.ReadFile(lockFile)
	if err != nil {
		return Lock{}, fmt.Errorf("failed to load lockfile: %w", err)
	}
	var lock Lock
	err = json.Unmarshal(payload, &lock)
	return lock, err
}

func (lock Lock) SaveToFile(lockFile string) error {
	jsonb, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshall json: %w", err)
	}
	// Github and pre-commit checks (like end-of-file-fixer) are expecting ASCII files
	// to end with a newline that marshal is not providing.
	jsonb = append(jsonb, '\n')
	// #nosec G306 -- apk world must be publicly readable
	return os.WriteFile(lockFile, jsonb, os.ModePerm)
}

// Arch2LockedPackages returns map: for each arch -> list of {package_name}={version} in archs.
func (lock Lock) Arch2LockedPackages(archs []types.Architecture) map[string][]string {
	wantedPackages := make(map[string][]string, len(archs))
	for _, p := range lock.Contents.Packages {
		arch := types.ParseArchitecture(p.Architecture)
		if slices.Contains(archs, arch) {
			wantedPackages[arch.String()] = append(
				wantedPackages[arch.String()],
				fmt.Sprintf("%s=%s", p.Name, p.Version),
			)
		}
	}
	return wantedPackages
}

// Architectures returns the architectures the lock file holds records for,
// normalized to their OCI form (amd64 rather than x86_64) and sorted.
//
// `apko lock` writes one record per architecture for every package it locks
// and for every repository it resolves against, so the union of the two is
// the set of architectures the lock file was generated for. The repositories
// matter: an architecture that resolves to no packages at all (an empty
// package list, or a base image that already provides everything requested)
// is still covered by the lock file, and its repository records say so.
//
// An empty result means the lock file carries no per-architecture records, in
// which case the architectures it was generated for cannot be determined.
func (lock Lock) Architectures() []types.Architecture {
	seen := map[types.Architecture]struct{}{}
	for _, p := range lock.Contents.Packages {
		seen[types.ParseArchitecture(p.Architecture)] = struct{}{}
	}
	for _, repos := range [][]LockRepo{
		lock.Contents.BuildRepositories,
		lock.Contents.RuntimeOnlyRepositories,
		lock.Contents.Repositories,
	} {
		for _, r := range repos {
			seen[types.ParseArchitecture(r.Architecture)] = struct{}{}
		}
	}
	// Records without an architecture say nothing about coverage.
	delete(seen, "")
	return slices.Sorted(maps.Keys(seen))
}

// MissingArchitectures returns the architectures in archs that the lock file
// was not generated for, deduplicated, in OCI form and in the order they were
// requested. Both APK and OCI spellings (x86_64 and amd64) are accepted.
//
// It returns nil when every requested architecture is covered. It also
// returns nil when the lock file carries no per-architecture records at all
// (see Architectures): coverage cannot be determined from such a lock file,
// so nothing is reported as missing.
func (lock Lock) MissingArchitectures(archs []types.Architecture) []types.Architecture {
	locked := lock.Architectures()
	if len(locked) == 0 {
		return nil
	}
	var missing []types.Architecture
	for _, a := range archs {
		arch := types.ParseArchitecture(a.String())
		if !slices.Contains(locked, arch) && !slices.Contains(missing, arch) {
			missing = append(missing, arch)
		}
	}
	return missing
}
