package paths

import (
	"os"
	"path"
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
