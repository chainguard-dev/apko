package build

import (
	"context"
	"slices"
	"testing"

	"chainguard.dev/apko/pkg/apk/fs"
)

func TestLdsoCache(t *testing.T) {
	ctx := context.Background()

	opts := []Option{
		WithConfig("apko.yaml", []string{"testdata"}),
	}

	bc, err := New(ctx, fs.NewMemFS(), opts...)
	if err != nil {
		t.Fatal(err)
	}
	// ld.so.cache is only generated if ld.so.conf exists
	f, err := bc.fs.Create("etc/ld.so.conf")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	err = bc.BuildImage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cache := "etc/ld.so.cache"
	info, err := bc.fs.Stat(cache)
	if err != nil {
		t.Fatal(err)
	}
	mode := info.Mode()
	perm := mode.Perm()
	if perm != 0644 {
		t.Errorf("%s has unexpected permissions: %v", cache, perm)
	}
}

func TestLdsoLibDirs(t *testing.T) {
	for _, tc := range []struct {
		name     string
		usrmerge bool
		confDirs []string
		want     []string
	}{{
		name:     "split lib",
		confDirs: []string{"/usr/local/lib"},
		want:     []string{"/usr/local/lib", "/lib", "/usr/lib"},
	}, {
		name:     "usrmerge skips /lib",
		usrmerge: true,
		confDirs: []string{"/usr/local/lib"},
		want:     []string{"/usr/local/lib", "/usr/lib"},
	}, {
		name:     "usrmerge skips /lib from ld.so.conf too",
		usrmerge: true,
		confDirs: []string{"/lib", "/opt/lib", "/usr/lib/"},
		want:     []string{"/opt/lib", "/usr/lib"},
	}, {
		name:     "conf dirs keep precedence over system dirs",
		confDirs: []string{"/usr/lib", "/opt/lib", "/opt/lib"},
		want:     []string{"/usr/lib", "/opt/lib", "/lib"},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fs.NewMemFS()
			if err := fsys.MkdirAll("usr/lib", 0755); err != nil {
				t.Fatal(err)
			}
			if tc.usrmerge {
				if err := fsys.Symlink("usr/lib", "lib"); err != nil {
					t.Fatal(err)
				}
			} else if err := fsys.MkdirAll("lib", 0755); err != nil {
				t.Fatal(err)
			}
			if got := ldsoLibDirs(fsys, tc.confDirs); !slices.Equal(got, tc.want) {
				t.Errorf("ldsoLibDirs() = %v, want %v", got, tc.want)
			}
		})
	}
}
