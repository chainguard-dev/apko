//go:build unix

package expandapk

import (
	"os"
	"syscall"
)

func isValidFileHandle(f *os.File) bool {
	fdInfo, err := f.Stat()
	if err != nil {
		return false
	}
	fdStat, ok := fdInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}

	pathInfo, err := os.Stat(f.Name())
	if err != nil {
		return false
	}
	pathStat, ok := pathInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}

	return fdStat.Dev == pathStat.Dev && fdStat.Ino == pathStat.Ino
}
