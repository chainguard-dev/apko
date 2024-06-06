package build

import (
	"fmt"
	"path/filepath"

	"golang.org/x/sys/unix"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
)

func installCharDevices(fsys apkfs.FullFS) error {
	devices := []struct {
		path  string
		major uint32
		minor uint32
	}{
		{"/dev/zero", 1, 5},
		{"/dev/urandom", 1, 9},
		{"/dev/null", 1, 3},
		{"/dev/random", 1, 8},
		{"/dev/console", 5, 1},
	}
	for _, dev := range devices {
		if _, err := fsys.Stat(dev.path); err == nil {
			continue
		}
		dir := filepath.Dir(dev.path)
		if err := fsys.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("creating directory %s: %w", dir, err)
		}
		if err := fsys.Mknod(dev.path, unix.S_IFCHR, int(unix.Mkdev(dev.major, dev.minor))); err != nil {
			return fmt.Errorf("creating character device %s: %w", dev.path, err)
		}
	}
	return nil
}
