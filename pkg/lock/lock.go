package lock

import (
	"encoding/json"
	"fmt"
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
	Keyrings            []LockKeyring `json:"keyring"`
	BuildRepositories   []LockRepo    `json:"build_repositories"`
	RuntimeRepositories []LockRepo    `json:"runtime_repositories"`
	Repositories        []LockRepo    `json:"repositories"`
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
