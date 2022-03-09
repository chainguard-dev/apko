package build

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
)

type Assertion func(*Context) error

func RequirePasswdFile(optional bool) Assertion {
	return func(bc *Context) error {
		path := filepath.Join(bc.WorkDir, "etc", "passwd")

		_, err := os.Stat(path)
		if err != nil && optional {
			log.Printf("warning: %s is missing", path)
			return nil
		}

		return fmt.Errorf("/etc/passwd file is missing: %w", err)
	}
}

func RequireGroupFile(optional bool) Assertion {
	return func(bc *Context) error {
		path := filepath.Join(bc.WorkDir, "etc", "group")

		_, err := os.Stat(path)
		if err != nil && optional {
			log.Printf("warning: %s is missing", path)
			return nil
		}

		return fmt.Errorf("/etc/group file is missing: %w", err)
	}
}
