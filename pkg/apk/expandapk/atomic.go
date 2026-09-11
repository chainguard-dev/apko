package expandapk

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// writeFileAtomic streams r into path by writing to a temporary file in the
// same directory and atomically renaming it into place.
func writeFileAtomic(path string, r io.Reader) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("creating temp file for %q: %w", path, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename below succeeds

	if _, err := io.Copy(tmp, r); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing %q: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("renaming %q onto %q: %w", tmpName, path, err)
	}
	return nil
}
