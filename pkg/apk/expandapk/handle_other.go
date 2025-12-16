//go:build !unix

package expandapk

import (
	"os"
)

func isValidFileHandle(_ *os.File) bool {
	return true
}
