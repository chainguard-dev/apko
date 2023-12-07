package lock

import (
	"encoding/json"
	"fmt"
	"os"
)

type Lock struct {
	Version  string       `json:"version"`
	Contents LockContents `json:"contents"`
}

type LockContents struct {
	Keyrings     []LockKeyring `json:"keyring"`
	Repositories []LockRepo    `json:"repositories"`
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
	Checksum     string                  `jsin:"checksum"` // populated since Apko 0.12
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

func FromFile(resolvedFile string) (Lock, error) {
	payload, err := os.ReadFile(resolvedFile)
	if err != nil {
		return Lock{}, fmt.Errorf("failed to load resolved-file: %w", err)
	}
	var lock Lock
	err = json.Unmarshal(payload, &lock)
	return lock, err
}

func (lock Lock) SaveToFile(resolvedFile string) error {
	jsonb, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshall json: %w", err)
	}

	return os.WriteFile(resolvedFile, jsonb, os.ModePerm)
}
